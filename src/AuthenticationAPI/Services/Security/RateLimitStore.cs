using AuthenticationAPI.Configuration;
using AuthenticationAPI.Utils.Logger;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AuthenticationAPI.Services.Security;

/// <summary>
/// Atomic fixed-window counters used for lockout and rate limiting.
/// Source of truth: the counter store itself (ephemeral by design). Durable security events go to SQL Server (SecurityEvents).
/// </summary>
public interface IRateLimitStore
{
    /// <summary>Atomically increments and returns the new count; the TTL is set when the key is created.</summary>
    Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default);
    /// <summary>Atomically decrements, never below zero.</summary>
    Task ReleaseAsync(string key, CancellationToken ct = default);
    Task<long> GetAsync(string key, CancellationToken ct = default);
    Task ResetAsync(string key, CancellationToken ct = default);
    Task ResetPrefixAsync(string prefix, CancellationToken ct = default);
}

public sealed class InMemoryRateLimitStore(int maxEntries = 100_000, TimeProvider? time = null) : IRateLimitStore
{
    private readonly Dictionary<string, (long Count, DateTimeOffset Expires)> _data = new();
    private readonly object _gate = new();
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            if (_data.TryGetValue(key, out var e) && e.Expires > now)
            {
                _data[key] = (e.Count + 1, e.Expires);
                return Task.FromResult(e.Count + 1);
            }

            if (_data.Count >= maxEntries) Evict(now);
            _data[key] = (1, now + window);
            return Task.FromResult(1L);
        }
    }

    public Task ReleaseAsync(string key, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_data.TryGetValue(key, out var e) && e.Count > 0) _data[key] = (e.Count - 1, e.Expires);
        }
        return Task.CompletedTask;
    }

    public Task<long> GetAsync(string key, CancellationToken ct = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_data.TryGetValue(key, out var e) && e.Expires > _time.GetUtcNow() ? e.Count : 0L);
        }
    }

    public Task ResetAsync(string key, CancellationToken ct = default)
    {
        lock (_gate) { _data.Remove(key); }
        return Task.CompletedTask;
    }

    public Task ResetPrefixAsync(string prefix, CancellationToken ct = default)
    {
        lock (_gate)
        {
            foreach (var k in _data.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal)).ToList()) _data.Remove(k);
        }
        return Task.CompletedTask;
    }

    // bounded memory: drop expired first, then the soonest-to-expire 10%
    private void Evict(DateTimeOffset now)
    {
        foreach (var k in _data.Where(kv => kv.Value.Expires <= now).Select(kv => kv.Key).ToList()) _data.Remove(k);
        if (_data.Count < maxEntries) return;
        foreach (var k in _data.OrderBy(kv => kv.Value.Expires).Take(Math.Max(1, maxEntries / 10)).Select(kv => kv.Key).ToList()) _data.Remove(k);
    }
}

public sealed class RedisRateLimitStore(IConnectionMultiplexer redis, IOptions<SecurityOptions> options) : IRateLimitStore
{
    private const string IncrScript = @"
local c = redis.call('INCR', KEYS[1])
if c == 1 or redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return c";

    private const string ReleaseScript = @"
local v = redis.call('GET', KEYS[1])
if v and tonumber(v) > 0 then return redis.call('DECR', KEYS[1]) end
return 0";

    private readonly string _prefix = options.Value.Redis.KeyPrefix;

    private IDatabase Db => redis.GetDatabase();

    public async Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        var result = await Db.ScriptEvaluateAsync(IncrScript, [(RedisKey)(_prefix + key)], [(RedisValue)(long)window.TotalMilliseconds]);
        return (long)result;
    }

    public async Task ReleaseAsync(string key, CancellationToken ct = default) =>
        await Db.ScriptEvaluateAsync(ReleaseScript, [(RedisKey)(_prefix + key)]);

    public async Task<long> GetAsync(string key, CancellationToken ct = default)
    {
        var v = await Db.StringGetAsync(_prefix + key);
        return v.HasValue && v.TryParse(out long n) ? n : 0;
    }

    public async Task ResetAsync(string key, CancellationToken ct = default) =>
        await Db.KeyDeleteAsync(_prefix + key);

    public async Task ResetPrefixAsync(string prefix, CancellationToken ct = default)
    {
        // SCAN-based (not KEYS). Not Redis-Cluster aware: iterates every primary endpoint; see docs/REDIS.md.
        foreach (var endpoint in redis.GetEndPoints())
        {
            var server = redis.GetServer(endpoint);
            if (server.IsReplica) continue;
            await foreach (var k in server.KeysAsync(pattern: _prefix + prefix + "*", pageSize: 250))
            {
                await Db.KeyDeleteAsync(k);
            }
        }
    }
}

/// <summary>
/// Failure policy: if Redis is unreachable, counters fall back to a per-process in-memory store.
/// Limits therefore stay ENFORCED (never fail-open) but are per instance until Redis recovers.
/// </summary>
public sealed class ResilientRateLimitStore(RedisRateLimitStore redis, InMemoryRateLimitStore fallback, IAppLogger<ResilientRateLimitStore> logger) : IRateLimitStore
{
    private long _lastWarnTicks;

    public Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
        Run(() => redis.IncrementAsync(key, window, ct), () => fallback.IncrementAsync(key, window, ct));

    public async Task ReleaseAsync(string key, CancellationToken ct = default)
    {
        await Run(async () => { await redis.ReleaseAsync(key, ct); return 0L; },
                  async () => { await fallback.ReleaseAsync(key, ct); return 0L; });
    }

    public Task<long> GetAsync(string key, CancellationToken ct = default) =>
        Run(() => redis.GetAsync(key, ct), () => fallback.GetAsync(key, ct));

    public async Task ResetAsync(string key, CancellationToken ct = default)
    {
        await fallback.ResetAsync(key, ct);
        await Run(async () => { await redis.ResetAsync(key, ct); return 0L; }, () => Task.FromResult(0L));
    }

    public async Task ResetPrefixAsync(string prefix, CancellationToken ct = default)
    {
        await fallback.ResetPrefixAsync(prefix, ct);
        await Run(async () => { await redis.ResetPrefixAsync(prefix, ct); return 0L; }, () => Task.FromResult(0L));
    }

    private async Task<T> Run<T>(Func<Task<T>> primary, Func<Task<T>> secondary)
    {
        try
        {
            return await primary();
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException or ObjectDisposedException or InvalidOperationException)
        {
            WarnThrottled(ex);
            AuthMetrics.RedisFallback.Add(1);
            return await secondary();
        }
    }

    private void WarnThrottled(Exception ex)
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastWarnTicks);
        if (now - last < 30_000 || Interlocked.CompareExchange(ref _lastWarnTicks, now, last) != last) return;
        logger.Error(ex, "Redis unavailable; rate limiting degraded to per-instance memory");
    }
}
