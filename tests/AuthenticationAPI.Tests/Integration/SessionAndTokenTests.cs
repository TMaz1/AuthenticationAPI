using System.Net;
using AuthenticationAPI.Models.Enums;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static AuthenticationAPI.Tests.Integration.ApiFixture;

namespace AuthenticationAPI.Tests.Integration;

[Trait("Category", "Integration")]
public class SessionAndTokenTests(ApiFixture fx) : IClassFixture<ApiFixture>
{
    [SqlFact]
    public async Task Refresh_rotates_the_token_and_the_new_pair_works_without_any_bearer_header()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var login = await fx.LoginAsync(c, user);

        var refreshed = await Post(fx.NewClient(), "/api/auth/refresh-token", new { token = login.RefreshToken }); // no Authorization header
        Assert.True(refreshed.Success, refreshed.Raw);
        Assert.NotEqual(login.RefreshToken, refreshed.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, (await Get(c, "/api/auth/user", refreshed.Token)).Status);
    }

    [SqlFact]
    public async Task Refresh_tokens_are_stored_only_as_hashes()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var login = await fx.LoginAsync(c, user);

        var hashes = await fx.Db(d => d.RefreshTokens.Where(r => r.UserId == user.Id).Select(r => r.TokenHash).ToListAsync());
        Assert.DoesNotContain(login.RefreshToken!, hashes);
        Assert.All(hashes, h => Assert.Equal(64, h.Length));
        Assert.Null(await fx.Db(async d => (await d.Users.AsNoTracking().SingleAsync(u => u.Id == user.Id)).RefreshToken)); // legacy plaintext column unused
    }

    [SqlFact]
    public async Task Reusing_a_consumed_refresh_token_revokes_the_whole_family()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var first = await fx.LoginAsync(c, user);
        var second = await Post(c, "/api/auth/refresh-token", new { token = first.RefreshToken });
        Assert.True(second.Success);

        var replay = await Post(c, "/api/auth/refresh-token", new { token = first.RefreshToken }); // stolen copy replayed
        Assert.Equal(HttpStatusCode.BadRequest, replay.Status);

        var legit = await Post(c, "/api/auth/refresh-token", new { token = second.RefreshToken }); // legitimate holder is cut off too
        Assert.Equal(HttpStatusCode.BadRequest, legit.Status);
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "refresh.reuse_detected" && e.UserId == user.Id)));
    }

    [SqlFact]
    public async Task Concurrent_refresh_requests_cannot_both_consume_one_token()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var login = await fx.LoginAsync(c, user);

        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => Post(fx.NewClient(), "/api/auth/refresh-token", new { token = login.RefreshToken })));
        Assert.Equal(1, results.Count(r => r.Success));
    }

    [SqlFact]
    public async Task Expired_revoked_malformed_and_foreign_refresh_tokens_are_rejected()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var login = await fx.LoginAsync(c, user);

        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = "garbage" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = new string('Z', 43) })).Status);

        await fx.Db(d => d.RefreshTokens.Where(r => r.UserId == user.Id).ExecuteUpdateAsync(s => s.SetProperty(r => r.ExpiresAt, DateTime.UtcNow.AddMinutes(-1))));
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = login.RefreshToken })).Status);

        var login2 = await fx.LoginAsync(c, user);
        await Post(c, "/api/auth/logout", null, login2.Token);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = login2.RefreshToken })).Status);
    }

    [SqlFact]
    public async Task Refresh_token_absolute_session_cap_is_enforced()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var login = await fx.LoginAsync(c, user);
        // pretend the login happened 100 days ago (cap is 90): the session cannot be renewed even though the token itself is unexpired
        await fx.Db(d => d.RefreshTokens.Where(r => r.UserId == user.Id).ExecuteUpdateAsync(s => s.SetProperty(r => r.AuthTime, DateTime.UtcNow.AddDays(-100))));
        var r = await Post(c, "/api/auth/refresh-token", new { token = login.RefreshToken });
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
    }

    [SqlFact]
    public async Task Remember_me_lengthens_the_refresh_token_lifetime()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var normal = await Post(c, "/api/auth/login", new { email = user.Email, password = user.Password, rememberMe = false });
        var persistent = await Post(c, "/api/auth/login", new { email = user.Email, password = user.Password, rememberMe = true });
        Assert.NotNull(normal.RefreshToken);
        Assert.NotNull(persistent.RefreshToken);

        var rows = await fx.Db(d => d.RefreshTokens.Where(r => r.UserId == user.Id).OrderBy(r => r.Id).Select(r => new { r.Persistent, r.ExpiresAt }).ToListAsync());
        var short_ = rows.Last(r => !r.Persistent).ExpiresAt;
        var long_ = rows.Last(r => r.Persistent).ExpiresAt;
        Assert.True(long_ - short_ > TimeSpan.FromDays(20));
    }

    [SqlFact]
    public async Task Logout_revokes_refresh_tokens()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var login = await fx.LoginAsync(c, user);
        Assert.True((await Post(c, "/api/auth/logout", null, login.Token)).Success);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = login.RefreshToken })).Status);
    }

    [SqlFact]
    public async Task Revoke_all_kills_access_and_refresh_tokens_across_sessions()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var a = await fx.LoginAsync(c, user);
        var b = await fx.LoginAsync(c, user);

        Assert.True((await Post(c, "/api/auth/sessions/revoke-all", null, a.Token)).Success);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Get(c, "/api/auth/user", b.Token)).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = b.RefreshToken })).Status);
    }

    [SqlFact]
    public async Task Disabling_an_account_takes_effect_immediately_for_access_refresh_and_login()
    {
        var c = fx.NewClient();
        var admin = await fx.RegisterVerifiedAsync(c, RoleType.Administrator);
        var user = await fx.RegisterVerifiedAsync(c);
        var session = await fx.LoginAsync(c, user);
        var adminToken = await fx.LoginTokenAsync(c, admin);

        Assert.True((await Post(c, "/api/auth/admin/disable", new { email = user.Email }, adminToken)).Success);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Get(c, "/api/auth/user", session.Token)).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = session.RefreshToken })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await fx.LoginAsync(c, user)).Status);

        Assert.True((await Post(c, "/api/auth/admin/enable", new { email = user.Email }, adminToken)).Success);
        Assert.Equal(HttpStatusCode.OK, (await fx.LoginAsync(c, user)).Status);
    }

    [SqlFact]
    public async Task Admin_actions_require_recent_authentication()
    {
        var c = fx.NewClient();
        var admin = await fx.RegisterVerifiedAsync(c, RoleType.Administrator);
        var user = await fx.RegisterVerifiedAsync(c);
        var login = await fx.LoginAsync(c, admin);

        // age the session's authentication beyond the allowed window, then refresh: auth_time must NOT be renewed by refresh
        await fx.Db(d => d.RefreshTokens.Where(r => r.UserId == admin.Id).ExecuteUpdateAsync(s => s.SetProperty(r => r.AuthTime, DateTime.UtcNow.AddMinutes(-60))));
        var refreshed = await Post(c, "/api/auth/refresh-token", new { token = login.RefreshToken });
        Assert.True(refreshed.Success);

        Assert.Equal(HttpStatusCode.Forbidden, (await Post(c, "/api/auth/admin/disable", new { email = user.Email }, refreshed.Token)).Status);
        Assert.Equal(HttpStatusCode.OK, (await Post(c, "/api/auth/admin/unlock", new { email = user.Email }, refreshed.Token)).Status); // low-risk action keeps AdminVerified
    }

    [SqlFact]
    public async Task Tampered_and_foreign_access_tokens_are_rejected()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var token = await fx.LoginTokenAsync(c, user);
        var parts = token.Split('.');

        Assert.Equal(HttpStatusCode.Unauthorized, (await Get(c, "/api/auth/user", parts[0] + "." + parts[1] + "." + new string('A', parts[2].Length))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Get(c, "/api/auth/user", "not.a.jwt")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Get(c, "/api/auth/user")).Status);
    }
}
