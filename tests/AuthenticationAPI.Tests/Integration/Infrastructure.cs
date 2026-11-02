using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Enums;
using AuthenticationAPI.Services.Notifications;
using AuthenticationAPI.Services.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OtpNet;
using Xunit;

namespace AuthenticationAPI.Tests.Integration;

/// <summary>Skipped unless AUTHAPI_TEST_SQL points at a SQL Server instance (see docs/TESTING.md). Never silently "passes".</summary>
public sealed class SqlFactAttribute : FactAttribute
{
    public const string EnvVar = "AUTHAPI_TEST_SQL";
    public SqlFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(EnvVar)))
            Skip = $"{EnvVar} is not set; SQL Server integration tests were NOT executed.";
    }
}

public sealed record SentEmail(string To, string Subject, string Html);
public sealed record SentSms(string To, string Message);

public sealed class FakeEmailSender : IEmailSender
{
    public ConcurrentQueue<SentEmail> Sent { get; } = new();
    private int _failNext;
    private int _attempts;
    public int Attempts => _attempts;
    public void FailNext(int n) => Interlocked.Exchange(ref _failNext, n);

    public Task SendAsync(string to, string subject, string htmlBody, CancellationToken ct)
    {
        Interlocked.Increment(ref _attempts);
        if (Interlocked.Decrement(ref _failNext) >= 0) throw new InvalidOperationException("simulated provider outage");
        Sent.Enqueue(new SentEmail(to, subject, htmlBody));
        return Task.CompletedTask;
    }

    public SentEmail? Last(string to, string subjectContains) =>
        Sent.Where(e => string.Equals(e.To, to, StringComparison.OrdinalIgnoreCase) && e.Subject.Contains(subjectContains)).LastOrDefault();
}

public sealed class FakeSmsSender : ISmsSender
{
    public ConcurrentQueue<SentSms> Sent { get; } = new();
    public Task SendAsync(string toE164, string message, CancellationToken ct)
    {
        Sent.Enqueue(new SentSms(toE164, message));
        return Task.CompletedTask;
    }
}

/// <summary>
/// Lets a test choose the client IP per request (TestServer has none),
/// so tests do not share throttle counters.
/// </summary>
internal sealed class TestIpStartupFilter : IStartupFilter
{
    public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(
        Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next) => app =>
    {
        app.Use((Microsoft.AspNetCore.Http.RequestDelegate nextMiddleware) =>
        {
            return async (Microsoft.AspNetCore.Http.HttpContext context) =>
            {
                if (context.Request.Headers.TryGetValue("X-Test-Ip", out var ipHeader))
                {
                    var ipText = ipHeader.ToString();

                    if (System.Net.IPAddress.TryParse(ipText, out var parsed))
                    {
                        context.Connection.RemoteIpAddress = parsed;
                    }
                }

                await nextMiddleware(context);
            };
        });

        next(app);
    };
}

public sealed class Resp(HttpStatusCode status, string raw, HttpResponseMessage message)
{
    public HttpStatusCode Status { get; } = status;
    public string Raw { get; } = raw;
    public HttpResponseMessage Message { get; } = message;
    private JsonElement Root => JsonDocument.Parse(string.IsNullOrWhiteSpace(Raw) ? "{}" : Raw).RootElement;
    public bool Success => Root.ValueKind == JsonValueKind.Object && Root.TryGetProperty("success", out var s) && s.ValueKind == JsonValueKind.True;
    public string Msg => Str("message") ?? "";
    public string? Str(params string[] path)
    {
        var e = Root;
        foreach (var p in path)
        {
            if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(p, out var next)) return null;
            e = next;
        }
        return e.ValueKind == JsonValueKind.String ? e.GetString() : e.ValueKind == JsonValueKind.Null ? null : e.ToString();
    }
    public string? Token => Str("data", "token");
    public string? RefreshToken => Str("data", "refreshToken");
    public string? Challenge => Str("data", "mfa", "challengeToken");
    public string? TrustedDevice => Str("data", "trustedDeviceToken");
}

public sealed record TestUser(int Id, string Email, string Password);

public class ApiFixture : IAsyncLifetime
{
    public const string Password = "Correct-horse-battery-1";
    public ApiFactory? Factory { get; private set; }
    public FakeEmailSender Email { get; } = new();
    public FakeSmsSender Sms { get; } = new();
    public string DatabaseName { get; } = "AuthApiTest_" + Guid.NewGuid().ToString("N")[..12];

    /// <summary>Per-fixture configuration overrides (key = "Section:Key").</summary>
    protected virtual Dictionary<string, string?> Overrides() => new();

    public Dictionary<string, string?> BuildSettings()
    {
        var baseCs = Environment.GetEnvironmentVariable(SqlFactAttribute.EnvVar)!.TrimEnd(';');
        var s = new Dictionary<string, string?>
        {
            ["ConnectionStrings:DefaultConnection"] = $"{baseCs};Database={DatabaseName}",
            ["ConnectionStrings:Redis"] = "127.0.0.1:1",
            ["AppSettings:Key"] = "integration-test-signing-key-0123456789-abcdef",
            ["AppSettings:Issuer"] = "https://issuer.test",
            ["AppSettings:Audience"] = "https://audience.test",
            ["AppSettings:AppLink"] = "https://app.test",
            ["Security:EncryptionKey"] = Convert.ToBase64String(Enumerable.Range(1, 32).Select(i => (byte)(i * 3)).ToArray()),
            ["Security:Password:Pbkdf2Iterations"] = "100000",
            ["Security:SessionCacheSeconds"] = "0",       // revocation must be visible immediately in tests
            ["Security:Redis:ConnectTimeoutMs"] = "200",
            ["Security:Redis:OperationTimeoutMs"] = "200",
            ["Security:Outbox:WorkersEnabled"] = "false", // tests pump the outbox deterministically
            ["Security:Outbox:MaxAttempts"] = "3",
            ["Security:Lockout:AccountIpMaxFailures"] = "5",
            ["Security:Lockout:AccountMaxFailures"] = "100000",
            ["Security:Lockout:IpMaxFailures"] = "100000",
            ["Security:Mfa:SmsEnabled"] = "true",
            ["Security:Sms:Provider"] = "Fake"
        };
        foreach (var name in new[] { "Register", "PasswordResetPerIp", "PasswordResetPerAccount", "ResendVerification", "TokenRedemption", "MfaVerifyPerIp", "MfaSend", "Refresh", "Reauthentication" })
            s[$"Security:RateLimits:{name}:Limit"] = "100000";
        foreach (var kv in Overrides()) s[kv.Key] = kv.Value;
        return s;
    }

    public async Task InitializeAsync()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(SqlFactAttribute.EnvVar))) return;
        Factory = new ApiFactory(this);
        await using var scope = Factory.Services.CreateAsyncScope();
        // applies the real migrations (including the hand-authored AddAuthHardening) to a real SQL Server database
        await scope.ServiceProvider.GetRequiredService<AuthDataContext>().Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        if (Factory is null)
            return;

        try
        {
            await using var scope = Factory.Services.CreateAsyncScope();

            var db = scope.ServiceProvider
                .GetRequiredService<AuthDataContext>();

            await db.Database.EnsureDeletedAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[TEST CLEANUP ERROR] Database: {DatabaseName}");
            Console.Error.WriteLine(ex);
        }
        finally
        {
            await Factory.DisposeAsync();
            Factory = null;
        }
    }

    private static int _ipCounter = 1;
    public HttpClient NewClient(string? ip = null)
    {
        var c = Factory!.CreateClient();
        var n = Interlocked.Increment(ref _ipCounter);
        c.DefaultRequestHeaders.Add("X-Test-Ip", ip ?? $"10.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}");
        return c;
    }

    public static HttpClient WithBearer(HttpClient c, string? token)
    {
        c.DefaultRequestHeaders.Authorization = token is null ? null : new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    public static async Task<Resp> Send(HttpClient c, HttpMethod m, string path, object? body = null, string? bearer = null)
    {
        using var req = new HttpRequestMessage(m, path);
        if (body is not null) req.Content = JsonContent.Create(body);
        if (bearer is not null) req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearer);
        var res = await c.SendAsync(req);
        return new Resp(res.StatusCode, await res.Content.ReadAsStringAsync(), res);
    }

    public static Task<Resp> Post(HttpClient c, string path, object? body = null, string? bearer = null) => Send(c, HttpMethod.Post, path, body, bearer);
    public static Task<Resp> Get(HttpClient c, string path, string? bearer = null) => Send(c, HttpMethod.Get, path, null, bearer);
    public static Task<Resp> Delete(HttpClient c, string path, string? bearer = null) => Send(c, HttpMethod.Delete, path, null, bearer);

    public async Task PumpAsync()
    {
        var p = Factory!.Services.GetRequiredService<OutboxProcessor>();
        while (await p.ProcessBatchAsync(CancellationToken.None) > 0) { }
    }

    public async Task<T> Db<T>(Func<AuthDataContext, Task<T>> action)
    {
        await using var scope = Factory!.Services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<AuthDataContext>());
    }

    public Task Db(Func<AuthDataContext, Task> action) => Db<int>(async d => { await action(d); return 0; });

    public string? TokenFromEmail(string to, string subjectContains)
    {
        var mail = Email.Last(to, subjectContains);
        var m = mail is null ? null : Regex.Match(mail.Html, @"token=([A-Za-z0-9_-]+)");
        return m is { Success: true } ? m.Groups[1].Value : null;
    }

    public string? OtpFromEmail(string to)
    {
        var mail = Email.Last(to, "One-Time MFA Code");
        var m = mail is null ? null : Regex.Match(mail.Html, @"<strong>(\d{6})</strong>");
        return m is { Success: true } ? m.Groups[1].Value : null;
    }

    public string? CodeFromSms(string to)
    {
        var sms = Sms.Sent.Where(s => s.To == to).LastOrDefault();
        var m = sms is null ? null : Regex.Match(sms.Message, @"code is (\d{6})");
        return m is { Success: true } ? m.Groups[1].Value : null;
    }

    public async Task<TestUser> RegisterVerifiedAsync(HttpClient c, RoleType? role = null)
    {
        var email = $"user-{Guid.NewGuid():N}@example.com";
        var reg = await Post(c, "/api/auth/register", new { email, password = Password, confirmPassword = Password, firstName = "Test", lastName = "User" });
        Assert.True(reg.Success, reg.Raw);
        await PumpAsync();
        var token = TokenFromEmail(email, "Verify");
        Assert.NotNull(token);
        var ver = await Post(c, "/api/auth/verify-account", new { token });
        Assert.True(ver.Success, ver.Raw);

        var id = await Db(async d =>
        {
            var u = await d.Users.SingleAsync(x => x.Email == email);
            if (role is not null) { u.Role = role.Value; await d.SaveChangesAsync(); }
            return u.Id;
        });
        return new TestUser(id, email, Password);
    }

    public Task<Resp> LoginAsync(HttpClient c, TestUser u, object? extra = null, string? password = null) =>
        Post(c, "/api/auth/login", new { email = u.Email, password = password ?? u.Password, rememberMe = false, trustedDeviceToken = extra });

    public async Task<string> LoginTokenAsync(HttpClient c, TestUser u)
    {
        var r = await LoginAsync(c, u);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Token!;
    }

    /// <summary>Current authenticator code for a user who completed MFA setup.</summary>
    public async Task<string> TotpFor(int userId, int stepOffset = 0)
    {
        var secret = await Db(async d =>
        {
            var u = await d.Users.AsNoTracking().SingleAsync(x => x.Id == userId);
            return Factory!.Services.GetRequiredService<ISecretProtector>().Unprotect(u.MfaSecretKey ?? u.PendingMfaSecret!, "mfa-secret");
        });
        return new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(DateTime.UtcNow.AddSeconds(30 * stepOffset));
    }

    /// <summary>Runs setup + enable for a verified user (password re-authentication included).</summary>
    public async Task EnableMfaAsync(HttpClient c, TestUser u)
    {
        var token = await LoginTokenAsync(c, u);
        var setup = await Get(c, "/api/auth/mfa/setup", token);
        Assert.True(setup.Success, setup.Raw);
        var enable = await Post(c, "/api/auth/mfa/enable", new { otpCode = await TotpFor(u.Id), password = u.Password }, token);
        Assert.True(enable.Success, enable.Raw);
    }

    public Task ClearTotpStep(int userId) => Db(d => d.Users.Where(x => x.Id == userId).ExecuteUpdateAsync(s => s.SetProperty(x => x.LastTotpStep, (long?)null)));

    public Task PromoteAsync(int userId, RoleType role) =>
        Db(d => d.Users.Where(x => x.Id == userId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Role, role)));
}

public sealed class ApiFactory(ApiFixture fixture) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        // UseSetting (not ConfigureAppConfiguration) so values are visible to code in Program.cs that reads configuration while registering services
        foreach (var kv in fixture.BuildSettings()) builder.UseSetting(kv.Key, kv.Value);

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEmailSender>();
            services.RemoveAll<ISmsSender>();
            services.RemoveAll<IRateLimitStore>();
            services.AddSingleton<IEmailSender>(fixture.Email);
            services.AddSingleton<ISmsSender>(fixture.Sms);
            services.AddSingleton<IRateLimitStore>(new InMemoryRateLimitStore());
            services.AddTransient<Microsoft.AspNetCore.Hosting.IStartupFilter, TestIpStartupFilter>();
        });
    }
}
