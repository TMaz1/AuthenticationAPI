using System.Net;
using AuthenticationAPI.Models.Enums;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static AuthenticationAPI.Tests.Integration.ApiFixture;

namespace AuthenticationAPI.Tests.Integration;

[Trait("Category", "Integration")]
public class AuthFlowTests(ApiFixture fx) : IClassFixture<ApiFixture>
{
    [SqlFact]
    public async Task Register_ignores_client_supplied_role_and_creates_a_viewer()
    {
        var c = fx.NewClient();
        var email = $"evil-{Guid.NewGuid():N}@example.com";
        var reg = await Post(c, "/api/auth/register", new { email, password = Password, confirmPassword = Password, firstName = "Eve", lastName = "Hacker", role = "Administrator" });
        Assert.True(reg.Success, reg.Raw);

        Assert.Equal(RoleType.Viewer, await fx.Db(async d => (await d.Users.SingleAsync(u => u.Email == email)).Role));
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "register.role_ignored")));
    }

    [SqlFact]
    public async Task Role_cannot_be_escalated_through_the_admin_endpoint_by_a_non_admin()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var token = await fx.LoginTokenAsync(c, user);

        var r = await Post(c, "/api/auth/admin/role", new { email = user.Email, role = "Administrator" }, token);
        Assert.Equal(HttpStatusCode.Forbidden, r.Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Post(c, "/api/auth/admin/role", new { email = user.Email, role = "Administrator" })).Status);
    }

    [SqlFact]
    public async Task Admin_can_change_role_which_immediately_invalidates_the_old_access_token_and_is_audited()
    {
        var c = fx.NewClient();
        var admin = await fx.RegisterVerifiedAsync(c, RoleType.Administrator);
        var user = await fx.RegisterVerifiedAsync(c);
        var adminToken = await fx.LoginTokenAsync(c, admin);
        var userToken = await fx.LoginTokenAsync(c, user);

        var r = await Post(c, "/api/auth/admin/role", new { email = user.Email, role = "Editor" }, adminToken);
        Assert.True(r.Success, r.Raw);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Get(c, "/api/auth/user", userToken)).Status); // stale role claim is dead
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "admin.role_changed" && e.ActorUserId == admin.Id && e.UserId == user.Id)));

        // admins cannot demote/disable themselves
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/admin/role", new { email = admin.Email, role = "Viewer" }, adminToken)).Status);
    }

    [SqlFact]
    public async Task Unknown_user_and_wrong_password_are_indistinguishable()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var wrong = await fx.LoginAsync(c, user, password: "definitely-not-it-1");
        var unknown = await Post(c, "/api/auth/login", new { email = $"nobody-{Guid.NewGuid():N}@example.com", password = "definitely-not-it-1" });

        Assert.Equal(wrong.Status, unknown.Status);
        Assert.Equal(wrong.Msg, unknown.Msg);
        Assert.Equal(HttpStatusCode.BadRequest, wrong.Status);
    }

    [SqlFact]
    public async Task Unverified_account_gets_a_token_that_is_not_verified_and_cannot_use_verified_endpoints_but_can_resend()
    {
        var c = fx.NewClient();
        var email = $"unv-{Guid.NewGuid():N}@example.com";
        await Post(c, "/api/auth/register", new { email, password = Password, confirmPassword = Password, firstName = "Una", lastName = "Verified" });

        var login = await Post(c, "/api/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.OK, login.Status);
        Assert.Null(login.RefreshToken); // no persistent session before verification
        Assert.Equal(HttpStatusCode.Forbidden, (await Get(c, "/api/auth/protected-resource", login.Token)).Status);

        var resend = await Post(c, "/api/auth/resend-verification", null, login.Token);
        Assert.True(resend.Success, resend.Raw);
        await fx.PumpAsync();
        Assert.NotNull(fx.TokenFromEmail(email, "Verify"));
    }

    [SqlFact]
    public async Task Concurrent_verification_redeems_the_token_exactly_once()
    {
        var c = fx.NewClient();
        var email = $"cv-{Guid.NewGuid():N}@example.com";
        await Post(c, "/api/auth/register", new { email, password = Password, confirmPassword = Password, firstName = "Con", lastName = "Current" });
        await fx.PumpAsync();
        var token = fx.TokenFromEmail(email, "Verify");

        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Post(fx.NewClient(), "/api/auth/verify-account", new { token })));
        Assert.Equal(1, results.Count(r => r.Success));
    }

    [SqlFact]
    public async Task Verification_tokens_are_stored_hashed_and_garbage_tokens_fail_generically()
    {
        var c = fx.NewClient();
        var email = $"hash-{Guid.NewGuid():N}@example.com";
        await Post(c, "/api/auth/register", new { email, password = Password, confirmPassword = Password, firstName = "Has", lastName = "Hed" });
        await fx.PumpAsync();
        var raw = fx.TokenFromEmail(email, "Verify")!;

        var stored = await fx.Db(async d => (await d.Users.SingleAsync(u => u.Email == email)).VerificationToken);
        Assert.NotNull(stored);
        Assert.NotEqual(raw, stored);
        Assert.Equal(64, stored!.Length);

        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/verify-account", new { token = "x" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/verify-account", new { token = new string('a', 43) })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/verify-account", new { token = stored })).Status); // the hash is not a credential
    }

    [SqlFact]
    public async Task Duplicate_registration_is_rejected_case_insensitively_and_weak_passwords_are_refused()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var dup = await Post(c, "/api/auth/register", new { email = user.Email.ToUpperInvariant(), password = Password, confirmPassword = Password, firstName = "Dup", lastName = "Licate" });
        Assert.Equal(HttpStatusCode.BadRequest, dup.Status);

        var weak = await Post(c, "/api/auth/register", new { email = $"w-{Guid.NewGuid():N}@example.com", password = "short", confirmPassword = "short", firstName = "Wee", lastName = "Weak" });
        Assert.Equal(HttpStatusCode.BadRequest, weak.Status);
    }

    [SqlFact]
    public async Task Test_email_endpoint_is_not_anonymous_and_is_hidden_outside_development()
    {
        var c = fx.NewClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await Post(c, "/api/auth/email/test/all?to=a@example.com")).Status);

        var admin = await fx.RegisterVerifiedAsync(c, RoleType.Administrator);
        Assert.Equal(HttpStatusCode.NotFound, (await Post(c, "/api/auth/email/test/all?to=a@example.com", null, await fx.LoginTokenAsync(c, admin))).Status);
    }

    [SqlFact]
    public async Task Legacy_password_hash_is_accepted_once_and_transparently_upgraded()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var salt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(128);
        using var hmac = new System.Security.Cryptography.HMACSHA512(salt);
        var legacyHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));
        await fx.Db(d => d.Users.Where(u => u.Id == user.Id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.PasswordHash, legacyHash).SetProperty(u => u.PasswordSalt, salt)
            .SetProperty(u => u.PasswordHashVersion, 1).SetProperty(u => u.PasswordHashIterations, (int?)null)));

        Assert.Equal(HttpStatusCode.OK, (await fx.LoginAsync(c, user)).Status);
        var after = await fx.Db(d => d.Users.AsNoTracking().SingleAsync(u => u.Id == user.Id));
        Assert.Equal(2, after.PasswordHashVersion);
        Assert.NotNull(after.PasswordHashIterations);
        Assert.Equal(HttpStatusCode.OK, (await fx.LoginAsync(c, user)).Status); // still works on the new hash
    }

    [SqlFact]
    public async Task Health_endpoints_expose_status_only()
    {
        var c = fx.NewClient();
        var live = await Get(c, "/health/live");
        Assert.Equal(HttpStatusCode.OK, live.Status);
        Assert.Equal("Healthy", live.Raw);

        var ready = await Get(c, "/health/ready"); // Redis is unreachable in this fixture => Degraded, still serving
        Assert.Equal(HttpStatusCode.OK, ready.Status);
        Assert.DoesNotContain("sql", ready.Raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("127.0.0.1", ready.Raw);
    }

    [SqlFact]
    public async Task Malformed_json_returns_problem_details_without_internal_detail()
    {
        var c = fx.NewClient();
        var res = await c.PostAsync("/api/auth/login", new StringContent("{ not json", System.Text.Encoding.UTF8, "application/json"));
        var body = await res.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.DoesNotContain("StackTrace", body, StringComparison.OrdinalIgnoreCase);
    }
}
