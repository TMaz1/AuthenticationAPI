using System.Net;
using AuthenticationAPI.Models.Enums;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static AuthenticationAPI.Tests.Integration.ApiFixture;

namespace AuthenticationAPI.Tests.Integration;

[Trait("Category", "Integration")]
public class PasswordRecoveryTests(ApiFixture fx) : IClassFixture<ApiFixture>
{
    private const string NewPassword = "An-entirely-new-passphrase-9";

    [SqlFact]
    public async Task Reset_request_gives_the_same_answer_for_known_and_unknown_emails_and_does_not_sign_anyone_out()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var session = await fx.LoginAsync(c, user);

        var known = await Post(c, "/api/auth/password-reset-request", new { email = user.Email });
        var unknown = await Post(c, "/api/auth/password-reset-request", new { email = $"ghost-{Guid.NewGuid():N}@example.com" });
        Assert.Equal(known.Status, unknown.Status);
        Assert.Equal(known.Msg, unknown.Msg);
        Assert.Equal(HttpStatusCode.OK, known.Status);

        // anyone can request a reset for anyone: it must not log the victim out
        Assert.Equal(HttpStatusCode.OK, (await Get(c, "/api/auth/user", session.Token)).Status);
        Assert.True((await Post(c, "/api/auth/refresh-token", new { token = session.RefreshToken })).Success);

        await fx.PumpAsync();
        Assert.NotNull(fx.TokenFromEmail(user.Email, "Reset"));
        Assert.Null(fx.TokenFromEmail($"ghost@example.com", "Reset"));
    }

    [SqlFact]
    public async Task Reset_changes_the_password_ends_all_sessions_and_does_not_log_in()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var session = await fx.LoginAsync(c, user);
        await Post(c, "/api/auth/password-reset-request", new { email = user.Email });
        await fx.PumpAsync();
        var token = fx.TokenFromEmail(user.Email, "Reset");

        var reset = await Post(c, "/api/auth/reset-password", new { email = user.Email, token, newPassword = NewPassword, confirmPassword = NewPassword });
        Assert.True(reset.Success, reset.Raw);
        Assert.Null(reset.Token);
        Assert.Null(reset.RefreshToken);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Get(c, "/api/auth/user", session.Token)).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = session.RefreshToken })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await fx.LoginAsync(c, user)).Status);                  // old password
        Assert.Equal(HttpStatusCode.OK, (await fx.LoginAsync(c, user, password: NewPassword)).Status);  // new password

        await fx.PumpAsync();
        Assert.NotNull(fx.Email.Last(user.Email, "password was changed")); // security notification
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "password.changed" && e.UserId == user.Id)));
    }

    [SqlFact]
    public async Task Reset_token_is_single_use_and_bound_to_its_account()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var other = await fx.RegisterVerifiedAsync(c);
        await Post(c, "/api/auth/password-reset-request", new { email = user.Email });
        await fx.PumpAsync();
        var token = fx.TokenFromEmail(user.Email, "Reset");

        var wrongAccount = await Post(c, "/api/auth/reset-password", new { email = other.Email, token, newPassword = NewPassword, confirmPassword = NewPassword });
        Assert.Equal(HttpStatusCode.BadRequest, wrongAccount.Status);

        Assert.True((await Post(c, "/api/auth/reset-password", new { email = user.Email, token, newPassword = NewPassword, confirmPassword = NewPassword })).Success);
        var replay = await Post(c, "/api/auth/reset-password", new { email = user.Email, token, newPassword = "Another-passphrase-77", confirmPassword = "Another-passphrase-77" });
        Assert.Equal(HttpStatusCode.BadRequest, replay.Status);
        Assert.Equal(HttpStatusCode.OK, (await fx.LoginAsync(c, other)).Status); // untouched
    }

    [SqlFact]
    public async Task Concurrent_redemption_of_a_reset_token_succeeds_exactly_once()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        await Post(c, "/api/auth/password-reset-request", new { email = user.Email });
        await fx.PumpAsync();
        var token = fx.TokenFromEmail(user.Email, "Reset");

        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(i =>
            Post(fx.NewClient(), "/api/auth/reset-password", new { email = user.Email, token, newPassword = $"Racing-passphrase-{i:00}x", confirmPassword = $"Racing-passphrase-{i:00}x" })));
        Assert.Equal(1, results.Count(r => r.Success));
    }

    [SqlFact]
    public async Task Weak_new_password_is_refused_without_burning_the_token_and_expired_tokens_fail()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        await Post(c, "/api/auth/password-reset-request", new { email = user.Email });
        await fx.PumpAsync();
        var token = fx.TokenFromEmail(user.Email, "Reset");

        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/reset-password", new { email = user.Email, token, newPassword = "short", confirmPassword = "short" })).Status);
        Assert.True((await Post(c, "/api/auth/reset-password", new { email = user.Email, token, newPassword = NewPassword, confirmPassword = NewPassword })).Success); // still usable

        await Post(c, "/api/auth/password-reset-request", new { email = user.Email });
        await fx.PumpAsync();
        var token2 = fx.TokenFromEmail(user.Email, "Reset");
        await fx.Db(d => d.Users.Where(u => u.Id == user.Id).ExecuteUpdateAsync(s => s.SetProperty(u => u.PasswordResetTokenExpires, (DateTime?)DateTime.UtcNow.AddMinutes(-1))));
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/reset-password", new { email = user.Email, token = token2, newPassword = "Yet-another-passphrase-5", confirmPassword = "Yet-another-passphrase-5" })).Status);
    }

    [SqlFact]
    public async Task Reset_tokens_are_stored_hashed()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        await Post(c, "/api/auth/password-reset-request", new { email = user.Email });
        await fx.PumpAsync();
        var raw = fx.TokenFromEmail(user.Email, "Reset");
        var stored = await fx.Db(async d => (await d.Users.AsNoTracking().SingleAsync(u => u.Id == user.Id)).PasswordResetToken);
        Assert.NotEqual(raw, stored);
        Assert.Equal(64, stored!.Length);
    }
}

public class LockoutFixture : ApiFixture
{
    protected override Dictionary<string, string?> Overrides() => new()
    {
        ["Security:Lockout:AccountIpMaxFailures"] = "3",
        ["Security:RateLimits:PasswordResetPerAccount:Limit"] = "2",
        ["Security:RateLimits:Register:Limit"] = "3"
    };
}

[Trait("Category", "Integration")]
public class LockoutTests(LockoutFixture fx) : IClassFixture<LockoutFixture>
{
    [SqlFact]
    public async Task Lockout_blocks_even_the_correct_password_then_admin_unlock_and_other_ips_are_unaffected()
    {
        var setup = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(setup);
        var admin = await fx.RegisterVerifiedAsync(setup, RoleType.Administrator);
        var adminToken = await fx.LoginTokenAsync(setup, admin);

        var attacker = fx.NewClient("203.0.113.9");
        for (var i = 0; i < 3; i++) Assert.Equal(HttpStatusCode.BadRequest, (await fx.LoginAsync(attacker, user, password: "wrong-password-1")).Status);

        var blocked = await fx.LoginAsync(attacker, user); // correct password, but locked
        Assert.Equal((HttpStatusCode)429, blocked.Status);
        Assert.True(blocked.Message.Headers.Contains("Retry-After"));

        Assert.Equal(HttpStatusCode.OK, (await fx.LoginAsync(fx.NewClient("198.51.100.20"), user)).Status); // the real owner elsewhere

        Assert.True((await Post(setup, "/api/auth/admin/unlock", new { email = user.Email }, adminToken)).Success);
        Assert.Equal(HttpStatusCode.OK, (await fx.LoginAsync(attacker, user)).Status);
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "admin.account_unlocked" && e.ActorUserId == admin.Id)));
    }

    [SqlFact]
    public async Task Concurrent_wrong_guesses_cannot_exceed_the_limit_and_unknown_emails_are_throttled_identically()
    {
        var setup = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(setup);
        var attacker = "203.0.113.50";

        var attempts = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => fx.LoginAsync(fx.NewClient(attacker), user, password: "wrong-password-1")));
        Assert.Equal(3, attempts.Count(r => r.Status == HttpStatusCode.BadRequest)); // only 3 guesses ever reached password verification
        Assert.Equal(17, attempts.Count(r => (int)r.Status == 429));

        var ghost = $"ghost-{Guid.NewGuid():N}@example.com";
        var ghostAttempts = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
            ghostAttempts.Add((await Post(fx.NewClient("203.0.113.51"), "/api/auth/login", new { email = ghost, password = "whatever-123" })).Status);
        Assert.Equal(new[] { HttpStatusCode.BadRequest, HttpStatusCode.BadRequest, HttpStatusCode.BadRequest, (HttpStatusCode)429, (HttpStatusCode)429 }, ghostAttempts.ToArray());
    }

    [SqlFact]
    public async Task Successful_login_does_not_consume_the_failure_budget()
    {
        var c = fx.NewClient("203.0.113.60");
        var user = await fx.RegisterVerifiedAsync(fx.NewClient());
        for (var i = 0; i < 10; i++) Assert.Equal(HttpStatusCode.OK, (await fx.LoginAsync(c, user)).Status);
    }

    [SqlFact]
    public async Task Password_reset_requests_are_limited_per_account_without_revealing_that()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(fx.NewClient());
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 4; i++) statuses.Add((await Post(c, "/api/auth/password-reset-request", new { email = user.Email })).Status);
        Assert.All(statuses, s => Assert.Equal(HttpStatusCode.OK, s)); // over-limit requests still answer 200 and simply send nothing

        await fx.PumpAsync();
        Assert.Equal(2, fx.Email.Sent.Count(e => e.To == user.Email && e.Subject.Contains("Reset")));
    }

    [SqlFact]
    public async Task Registration_is_rate_limited_per_ip()
    {
        var c = fx.NewClient("203.0.113.70");
        var codes = new List<int>();
        for (var i = 0; i < 5; i++)
            codes.Add((int)(await Post(c, "/api/auth/register", new { email = $"rl-{Guid.NewGuid():N}@example.com", password = ApiFixture.Password, confirmPassword = ApiFixture.Password, firstName = "Rate", lastName = "Limit" })).Status);
        Assert.Equal(3, codes.Count(x => x == 200));
        Assert.Equal(2, codes.Count(x => x == 429));
    }
}
