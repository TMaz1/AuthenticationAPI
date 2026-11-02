using AuthenticationAPI.Configuration;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Tests.Unit;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Xunit;

namespace AuthenticationAPI.Tests.Integration;

/// <summary>Skipped unless AUTHAPI_TEST_REDIS (e.g. "localhost:6379") points at a real Redis. Exercises the Lua scripts for real.</summary>
public sealed class RedisFactAttribute : FactAttribute
{
    public const string EnvVar = "AUTHAPI_TEST_REDIS";
    public RedisFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(EnvVar)))
            Skip = $"{EnvVar} is not set; Redis integration tests were NOT executed.";
    }
}

[Trait("Category", "Integration")]
public class RedisRateLimitStoreTests
{
    private static RedisRateLimitStore Make(out ConnectionMultiplexer mux, out string prefix)
    {
        mux = ConnectionMultiplexer.Connect(Environment.GetEnvironmentVariable(RedisFactAttribute.EnvVar)!);
        prefix = "test-" + Guid.NewGuid().ToString("N")[..8] + ":";
        return new RedisRateLimitStore(mux, Options.Create(new SecurityOptions { Redis = new RedisOptions { KeyPrefix = prefix } }));
    }

    [RedisFact]
    public async Task Increment_is_atomic_under_concurrency_and_sets_a_ttl()
    {
        var store = Make(out var mux, out var prefix);
        using (mux)
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 200).Select(_ => store.IncrementAsync("k", TimeSpan.FromSeconds(30))));
            Assert.Equal(200, results.Distinct().Count());
            var ttl = await mux.GetDatabase().KeyTimeToLiveAsync(prefix + "k");
            Assert.NotNull(ttl);
            Assert.InRange(ttl!.Value.TotalSeconds, 1, 30);
        }
    }

    [RedisFact]
    public async Task Window_expires_release_floors_at_zero_and_prefix_reset_works()
    {
        var store = Make(out var mux, out _);
        using (mux)
        {
            await store.IncrementAsync("short", TimeSpan.FromMilliseconds(300));
            await Task.Delay(600);
            Assert.Equal(0, await store.GetAsync("short"));

            await store.ReleaseAsync("floor");
            Assert.Equal(0, await store.GetAsync("floor"));

            await store.IncrementAsync("grp:1", TimeSpan.FromMinutes(1));
            await store.IncrementAsync("grp:2", TimeSpan.FromMinutes(1));
            await store.IncrementAsync("other", TimeSpan.FromMinutes(1));
            await store.ResetPrefixAsync("grp:");
            Assert.Equal(0, await store.GetAsync("grp:1"));
            Assert.Equal(0, await store.GetAsync("grp:2"));
            Assert.Equal(1, await store.GetAsync("other"));
        }
    }

    [RedisFact]
    public async Task Login_throttle_on_real_redis_admits_exactly_the_limit_under_concurrency()
    {
        var store = Make(out var mux, out _);
        using (mux)
        {
            var t = new LoginThrottle(store, T.Sec());
            var email = $"{Guid.NewGuid():N}@example.com";
            var results = await Task.WhenAll(Enumerable.Range(0, 100).Select(_ => t.TryReserveAttemptAsync(email, "1.2.3.4")));
            Assert.Equal(5, results.Count(r => r));
            await t.UnlockAsync(email);
            Assert.True(await t.TryReserveAttemptAsync(email, "1.2.3.4"));
        }
    }
}
