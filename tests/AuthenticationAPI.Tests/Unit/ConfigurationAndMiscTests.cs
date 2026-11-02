using System.Security.Claims;
using AuthenticationAPI.Configuration;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Services.Notifications;
using AuthenticationAPI.Startup;
using FsCheck.Xunit;
using Microsoft.AspNetCore.Authorization;
using Xunit;

namespace AuthenticationAPI.Tests.Unit;

[Trait("Category", "Unit")]
public class OptionsValidationTests
{
    private static SecurityOptions Valid() => T.Sec().Value;
    private static bool Ok(SecurityOptions o) => new SecurityOptionsValidator().Validate(null, o).Succeeded;

    [Fact] public void Defaults_with_a_real_key_are_valid() => Assert.True(Ok(Valid()));

    [Theory]
    [InlineData("")]
    [InlineData("<BASE64_32_BYTE_KEY>")]
    [InlineData("dG9vc2hvcnQ=")]
    public void Missing_placeholder_or_short_encryption_key_fails_startup(string key)
    {
        var o = Valid(); o.EncryptionKey = key;
        Assert.False(Ok(o));
    }

    [Fact] public void Weak_pbkdf2_iterations_fail() { var o = Valid(); o.Password.Pbkdf2Iterations = 1000; Assert.False(Ok(o)); }
    [Fact] public void Min_password_length_below_8_fails() { var o = Valid(); o.Password.MinLength = 4; Assert.False(Ok(o)); }
    [Fact] public void Account_limit_below_pair_limit_fails() { var o = Valid(); o.Lockout.AccountMaxFailures = 2; Assert.False(Ok(o)); }
    [Fact] public void Zero_rate_limit_fails() { var o = Valid(); o.RateLimits.Register.Limit = 0; Assert.False(Ok(o)); }
    [Fact] public void Wildcard_cors_origin_fails() { var o = Valid(); o.Cors.AllowedOrigins = ["*"]; Assert.False(Ok(o)); }
    [Fact] public void Explicit_https_cors_origin_is_valid() { var o = Valid(); o.Cors.AllowedOrigins = ["https://app.example.com"]; Assert.True(Ok(o)); }
    [Fact] public void Invalid_proxy_ip_fails() { var o = Valid(); o.ForwardedHeaders.KnownProxies = ["not-an-ip"]; Assert.False(Ok(o)); }
    [Fact] public void Sms_enabled_without_a_provider_fails() { var o = Valid(); o.Mfa.SmsEnabled = true; o.Sms.Provider = "None"; Assert.False(Ok(o)); }
    [Fact] public void Sms_enabled_with_a_provider_is_valid() { var o = Valid(); o.Mfa.SmsEnabled = true; o.Sms.Provider = "Twilio-adapter"; Assert.True(Ok(o)); }
    [Fact] public void Absurd_mfa_attempt_limit_fails() { var o = Valid(); o.Mfa.ChallengeMaxAttempts = 1000; Assert.False(Ok(o)); }
    [Fact] public void Audit_retention_under_30_days_fails() { var o = Valid(); o.AuditRetentionDays = 7; Assert.False(Ok(o)); }

    private static bool JwtOk(Action<JwtSettings> t) => new JwtSettingsValidator().Validate(null, T.Jwt(t)).Succeeded;

    [Fact] public void Jwt_defaults_are_valid() => Assert.True(JwtOk(_ => { }));
    [Fact] public void Placeholder_jwt_key_fails() => Assert.False(JwtOk(j => j.Key = "<JWT_SECRET_KEY>"));
    [Fact] public void Short_jwt_key_fails() => Assert.False(JwtOk(j => j.Key = "short"));
    [Fact] public void Weak_previous_key_fails() => Assert.False(JwtOk(j => j.PreviousKeys = ["short"]));
    [Fact] public void Long_lived_access_token_fails() => Assert.False(JwtOk(j => j.AccessTokenExpiration = 24 * 60));
    [Fact] public void Missing_issuer_fails() => Assert.False(JwtOk(j => j.Issuer = ""));
    [Fact] public void Remember_me_shorter_than_default_session_fails() => Assert.False(JwtOk(j => { j.RefreshTokenExpiration = 30; j.RememberMeRefreshTokenExpiration = 7; }));
    [Fact] public void Huge_clock_skew_fails() => Assert.False(JwtOk(j => j.ClockSkewSeconds = 3600));

    [Fact]
    public void Smtp_configuration_detection()
    {
        Assert.False(ServiceCollectionExtensions.SmtpConfigured(new SmtpSettings { Host = "<SMTP_HOST>", FromEmail = "<FROM_EMAIL>" }));
        Assert.False(ServiceCollectionExtensions.SmtpConfigured(new SmtpSettings()));
        Assert.True(ServiceCollectionExtensions.SmtpConfigured(new SmtpSettings { Host = "smtp.example.com", FromEmail = "noreply@example.com" }));
    }
}

[Trait("Category", "Unit")]
public class OutboxBackoffTests
{
    private static readonly OutboxOptions O = new() { BaseDelaySeconds = 10, MaxDelayMinutes = 60 };

    [Fact]
    public void Grows_exponentially_without_jitter_and_caps()
    {
        Assert.Equal(TimeSpan.FromSeconds(10), OutboxBackoff.ComputeDelay(1, O, 1.0));
        Assert.Equal(TimeSpan.FromSeconds(20), OutboxBackoff.ComputeDelay(2, O, 1.0));
        Assert.Equal(TimeSpan.FromSeconds(40), OutboxBackoff.ComputeDelay(3, O, 1.0));
        Assert.Equal(TimeSpan.FromMinutes(60), OutboxBackoff.ComputeDelay(30, O, 1.0));
    }

    [Fact]
    public void Jitter_lowers_the_delay_to_at_least_half() =>
        Assert.Equal(TimeSpan.FromSeconds(5), OutboxBackoff.ComputeDelay(1, O, 0.0));

    [Property]
    public bool Delay_is_always_within_bounds(int attempt, byte jitter)
    {
        var d = OutboxBackoff.ComputeDelay(attempt, O, jitter / 255.0);
        return d >= TimeSpan.Zero && d <= TimeSpan.FromMinutes(O.MaxDelayMinutes);
    }

    [Property]
    public bool Delay_never_decreases_as_attempts_increase(byte a, byte jitter)
    {
        var attempt = a % 25 + 1;
        var j = jitter / 255.0;
        return OutboxBackoff.ComputeDelay(attempt + 1, O, j) >= OutboxBackoff.ComputeDelay(attempt, O, j);
    }
}

[Trait("Category", "Unit")]
public class RecentAuthenticationHandlerTests
{
    private static async Task<bool> Run(Claim[] claims, int minutes = 15, DateTimeOffset? now = null)
    {
        var handler = new RecentAuthenticationHandler(T.Sec(o => o.AdminRecentAuthMinutes = minutes), new FakeTime(now ?? DateTimeOffset.UtcNow));
        var req = new RecentAuthenticationRequirement();
        var ctx = new AuthorizationHandlerContext([req], new ClaimsPrincipal(new ClaimsIdentity(claims, "test")), null);
        await handler.HandleAsync(ctx);
        return ctx.HasSucceeded;
    }

    private static Claim AuthTime(DateTimeOffset t) => new("auth_time", t.ToUnixTimeSeconds().ToString());

    [Fact] public async Task Recent_authentication_succeeds() => Assert.True(await Run([AuthTime(DateTimeOffset.UtcNow.AddMinutes(-5))]));
    [Fact] public async Task Stale_authentication_fails() => Assert.False(await Run([AuthTime(DateTimeOffset.UtcNow.AddMinutes(-16))]));
    [Fact] public async Task Missing_claim_fails_closed() => Assert.False(await Run([]));
    [Fact] public async Task Malformed_claim_fails_closed() => Assert.False(await Run([new Claim("auth_time", "yesterday")]));
    [Fact] public async Task Far_future_claim_fails_closed() => Assert.False(await Run([AuthTime(DateTimeOffset.UtcNow.AddDays(5))]));
}

[Trait("Category", "Unit")]
public class ServiceGuardTests
{
    [Fact]
    public async Task Expected_failures_keep_their_kind_and_message()
    {
        var r = await ServiceGuard.RunAsync<bool>(() => throw new AuthException(ResultKind.TooManyRequests, "slow down") { RetryAfterSeconds = 9 }, _ => { });
        Assert.False(r.Success);
        Assert.Equal(ResultKind.TooManyRequests, r.Kind);
        Assert.Equal("slow down", r.Message);
        Assert.Equal(9, r.RetryAfterSeconds);
    }

    [Fact]
    public async Task Unexpected_exceptions_never_leak_their_message()
    {
        Exception? seen = null;
        var r = await ServiceGuard.RunAsync<bool>(() => throw new InvalidOperationException("Cannot open database 'Prod' Server=10.0.0.5;Password=hunter2"), e => seen = e);
        Assert.Equal(ResultKind.ServerError, r.Kind);
        Assert.DoesNotContain("hunter2", r.Message);
        Assert.DoesNotContain("Server=", r.Message);
        Assert.NotNull(seen);
    }

    [Fact]
    public async Task Cancellation_propagates()
    {
        await Assert.ThrowsAsync<OperationCanceledException>(() => ServiceGuard.RunAsync<bool>(() => throw new OperationCanceledException(), _ => { }));
    }
}
