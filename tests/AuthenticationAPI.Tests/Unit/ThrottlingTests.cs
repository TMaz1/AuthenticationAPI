using AuthenticationAPI.Configuration;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Utils.Logger;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Xunit;

namespace AuthenticationAPI.Tests.Unit;

[Trait("Category", "Unit")]
public class InMemoryRateLimitStoreTests
{
    [Fact]
    public async Task Increment_counts_and_expires_with_the_window()
    {
        var time = new FakeTime(DateTimeOffset.UtcNow);
        var store = new InMemoryRateLimitStore(time: time);

        Assert.Equal(1, await store.IncrementAsync("k", TimeSpan.FromSeconds(10)));
        Assert.Equal(2, await store.IncrementAsync("k", TimeSpan.FromSeconds(10)));
        Assert.Equal(2, await store.GetAsync("k"));

        time.Advance(TimeSpan.FromSeconds(11));
        Assert.Equal(0, await store.GetAsync("k"));
        Assert.Equal(1, await store.IncrementAsync("k", TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task Concurrent_increments_are_atomic()
    {
        var store = new InMemoryRateLimitStore();
        var results = await Task.WhenAll(Enumerable.Range(0, 500).Select(_ => Task.Run(() => store.IncrementAsync("k", TimeSpan.FromMinutes(1)))));
        Assert.Equal(500, results.Distinct().Count());
        Assert.Equal(500, results.Max());
    }

    [Fact]
    public async Task Release_never_goes_below_zero()
    {
        var store = new InMemoryRateLimitStore();
        await store.ReleaseAsync("k");
        Assert.Equal(0, await store.GetAsync("k"));
        await store.IncrementAsync("k", TimeSpan.FromMinutes(1));
        await store.ReleaseAsync("k");
        await store.ReleaseAsync("k");
        Assert.Equal(0, await store.GetAsync("k"));
    }

    [Fact]
    public async Task Reset_and_prefix_reset_only_touch_matching_keys()
    {
        var store = new InMemoryRateLimitStore();
        foreach (var k in new[] { "a:1", "a:2", "b:1" }) await store.IncrementAsync(k, TimeSpan.FromMinutes(1));
        await store.ResetPrefixAsync("a:");
        Assert.Equal(0, await store.GetAsync("a:1"));
        Assert.Equal(0, await store.GetAsync("a:2"));
        Assert.Equal(1, await store.GetAsync("b:1"));
        await store.ResetAsync("b:1");
        Assert.Equal(0, await store.GetAsync("b:1"));
    }

    [Fact]
    public async Task Memory_is_bounded()
    {
        var store = new InMemoryRateLimitStore(maxEntries: 100);
        for (var i = 0; i < 1000; i++) await store.IncrementAsync("k" + i, TimeSpan.FromMinutes(5));
        var present = 0;
        for (var i = 0; i < 1000; i++) if (await store.GetAsync("k" + i) > 0) present++;
        Assert.InRange(present, 1, 100);
    }
}

[Trait("Category", "Unit")]
public class LoginThrottleTests
{
    private static LoginThrottle Make(out InMemoryRateLimitStore store, Action<SecurityOptions>? tweak = null)
    {
        store = new InMemoryRateLimitStore();
        return new LoginThrottle(store, T.Sec(o => { o.Lockout.AccountIpMaxFailures = 5; o.Lockout.AccountMaxFailures = 20; o.Lockout.IpMaxFailures = 100; tweak?.Invoke(o); }));
    }

    [Fact]
    public async Task Pair_is_blocked_after_the_limit_and_the_sixth_attempt_is_refused()
    {
        var t = Make(out _);
        for (var i = 0; i < 5; i++) Assert.True(await t.TryReserveAttemptAsync("a@x.com", "1.1.1.1"));
        Assert.False(await t.TryReserveAttemptAsync("a@x.com", "1.1.1.1"));
    }

    [Fact]
    public async Task Attacker_ip_does_not_lock_the_victim_out_from_their_own_ip()
    {
        var t = Make(out _);
        for (var i = 0; i < 500; i++) await t.TryReserveAttemptAsync("victim@x.com", "6.6.6.6"); // hammering from one address
        Assert.False(await t.TryReserveAttemptAsync("victim@x.com", "6.6.6.6"));
        Assert.True(await t.TryReserveAttemptAsync("victim@x.com", "2.2.2.2")); // legitimate owner on another address
    }

    [Fact]
    public async Task Distributed_guessing_is_still_bounded_by_the_account_wide_limit()
    {
        var t = Make(out _);
        var allowed = 0;
        for (var i = 0; i < 100; i++) if (await t.TryReserveAttemptAsync("a@x.com", $"10.0.0.{i}")) allowed++;
        Assert.Equal(20, allowed);
    }

    [Fact]
    public async Task Ip_wide_limit_stops_credential_stuffing_across_accounts()
    {
        var t = Make(out _, o => o.Lockout.IpMaxFailures = 30);
        var allowed = 0;
        for (var i = 0; i < 100; i++) if (await t.TryReserveAttemptAsync($"user{i}@x.com", "9.9.9.9")) allowed++;
        Assert.Equal(30, allowed);
    }

    [Fact]
    public async Task Successful_login_releases_the_reservation()
    {
        var t = Make(out _);
        for (var i = 0; i < 50; i++)
        {
            Assert.True(await t.TryReserveAttemptAsync("a@x.com", "1.1.1.1"));
            await t.ReleaseAttemptAsync("a@x.com", "1.1.1.1");
        }
    }

    [Fact]
    public async Task Email_is_normalised_so_case_tricks_do_not_evade_the_limit()
    {
        var t = Make(out _);
        for (var i = 0; i < 5; i++) await t.TryReserveAttemptAsync(i % 2 == 0 ? "A@X.com" : "  a@x.COM ", "1.1.1.1");
        Assert.False(await t.TryReserveAttemptAsync("a@x.com", "1.1.1.1"));
    }

    [Fact]
    public async Task Unlock_clears_account_and_pair_counters()
    {
        var t = Make(out _);
        for (var i = 0; i < 6; i++) await t.TryReserveAttemptAsync("a@x.com", "1.1.1.1");
        Assert.False(await t.TryReserveAttemptAsync("a@x.com", "1.1.1.1"));
        await t.UnlockAsync("A@x.com");
        Assert.True(await t.TryReserveAttemptAsync("a@x.com", "1.1.1.1"));
    }

    [Fact]
    public async Task Concurrent_guesses_cannot_exceed_the_limit()
    {
        var t = Make(out _);
        var results = await Task.WhenAll(Enumerable.Range(0, 200).Select(_ => Task.Run(() => t.TryReserveAttemptAsync("a@x.com", "1.1.1.1"))));
        Assert.Equal(5, results.Count(r => r)); // exactly the configured number of guesses get through
    }

    [Fact]
    public async Task Counters_never_contain_the_raw_email_or_ip()
    {
        var store = new RecordingStore();
        var t = new LoginThrottle(store, T.Sec());
        await t.TryReserveAttemptAsync("secret.person@example.com", "203.0.113.77");
        Assert.All(store.Keys, k => { Assert.DoesNotContain("secret", k); Assert.DoesNotContain("203.0.113.77", k); });
    }

    private sealed class RecordingStore : IRateLimitStore
    {
        public List<string> Keys { get; } = [];
        public Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) { Keys.Add(key); return Task.FromResult(1L); }
        public Task ReleaseAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
        public Task<long> GetAsync(string key, CancellationToken ct = default) => Task.FromResult(0L);
        public Task ResetAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
        public Task ResetPrefixAsync(string prefix, CancellationToken ct = default) => Task.CompletedTask;
    }
}

[Trait("Category", "Unit")]
public class AbuseGuardTests
{
    [Fact]
    public async Task Throws_429_after_limit_and_scopes_by_identifier()
    {
        var guard = new AbuseGuard(new InMemoryRateLimitStore());
        var rule = new RateLimitRule(3, 60);
        for (var i = 0; i < 3; i++) await guard.EnforceAsync("p", rule, default, "ip1");

        var ex = await Assert.ThrowsAsync<AuthException>(() => guard.EnforceAsync("p", rule, default, "ip1"));
        Assert.Equal(ResultKind.TooManyRequests, ex.Kind);
        Assert.Equal(60, ex.RetryAfterSeconds);

        await guard.EnforceAsync("p", rule, default, "ip2");        // other identifier unaffected
        await guard.EnforceAsync("other", rule, default, "ip1");    // other policy unaffected
    }
}

[Trait("Category", "Unit")]
public class ResilientRateLimitStoreTests
{
    [Fact]
    public async Task When_redis_is_unreachable_limits_are_still_enforced_from_memory_never_fail_open()
    {
        // a REAL multiplexer pointed at a closed port: exercises the real failure path, not a mock
        var options = ConfigurationOptions.Parse("127.0.0.1:1");
        options.AbortOnConnectFail = false;
        options.ConnectTimeout = 200;
        options.SyncTimeout = 200;
        options.AsyncTimeout = 200;
        using var mux = ConnectionMultiplexer.Connect(options);

        var sec = T.Sec();
        var store = new ResilientRateLimitStore(new RedisRateLimitStore(mux, sec), new InMemoryRateLimitStore(), new NoopLogger<ResilientRateLimitStore>());

        Assert.Equal(1, await store.IncrementAsync("k", TimeSpan.FromMinutes(1)));
        Assert.Equal(2, await store.IncrementAsync("k", TimeSpan.FromMinutes(1)));
        await store.ReleaseAsync("k");
        Assert.Equal(1, await store.GetAsync("k"));
        await store.ResetAsync("k");
        Assert.Equal(0, await store.GetAsync("k"));

        var throttle = new LoginThrottle(store, T.Sec());
        var allowed = 0;
        for (var i = 0; i < 20; i++) if (await throttle.TryReserveAttemptAsync("a@x.com", "1.1.1.1")) allowed++;
        Assert.Equal(5, allowed);
    }
}

public sealed class NoopLogger<T> : IAppLogger<T>
{
    public void Info(string messageTemplate, params object[] values) { }
    public void Warn(string messageTemplate, params object[] values) { }
    public void Error(Exception ex, string messageTemplate, params object[] values) { }
    public void Debug(string messageTemplate, params object[] values) { }
}
