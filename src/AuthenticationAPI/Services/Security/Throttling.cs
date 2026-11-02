using AuthenticationAPI.Configuration;
using AuthenticationAPI.Dtos;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Security;

public interface ILoginThrottle
{
    /// <summary>
    /// Reserves one attempt for (account, ip) BEFORE the password is verified. Because the reservation is an atomic
    /// increment, N concurrent guesses cannot exceed the limit. Returns false if any scope is over its limit.
    /// </summary>
    Task<bool> TryReserveAttemptAsync(string email, string ip, CancellationToken ct = default);
    /// <summary>Releases the reservation after a successful authentication so only failures accumulate.</summary>
    Task ReleaseAttemptAsync(string email, string ip, CancellationToken ct = default);
    Task UnlockAsync(string email, CancellationToken ct = default);
    int RetryAfterSeconds { get; }
}

public sealed class LoginThrottle(IRateLimitStore store, IOptions<SecurityOptions> options) : ILoginThrottle
{
    private readonly LockoutOptions _o = options.Value.Lockout;
    private TimeSpan Window => TimeSpan.FromMinutes(_o.WindowMinutes);
    public int RetryAfterSeconds => _o.WindowMinutes * 60;

    // Identifiers are hashed: no emails or raw IPs in Redis keys.
    private static string AcctIp(string email, string ip) => $"login:ai:{Identifiers.Hash(Identifiers.NormalizeEmail(email), 24)}:{Identifiers.Hash(ip, 16)}";
    private static string Acct(string email) => $"login:a:{Identifiers.Hash(Identifiers.NormalizeEmail(email), 24)}";
    private static string Ip(string ip) => $"login:ip:{Identifiers.Hash(ip, 16)}";

    public async Task<bool> TryReserveAttemptAsync(string email, string ip, CancellationToken ct = default)
    {
        // Narrowest scope first and short-circuit: attempts already refused for an attacker's (account, IP) pair or IP
        // must NOT consume the account-wide budget, otherwise one IP could exhaust it and lock the real owner out.
        var pair = await store.IncrementAsync(AcctIp(email, ip), Window, ct);
        if (pair > _o.AccountIpMaxFailures) return false;

        var byIp = await store.IncrementAsync(Ip(ip), Window, ct);
        if (byIp > _o.IpMaxFailures) return false;

        var acct = await store.IncrementAsync(Acct(email), Window, ct);
        return acct <= _o.AccountMaxFailures;
    }

    public async Task ReleaseAttemptAsync(string email, string ip, CancellationToken ct = default)
    {
        await store.ReleaseAsync(AcctIp(email, ip), ct);
        await store.ReleaseAsync(Acct(email), ct);
        await store.ReleaseAsync(Ip(ip), ct);
    }

    public async Task UnlockAsync(string email, CancellationToken ct = default)
    {
        await store.ResetAsync(Acct(email), ct);
        await store.ResetPrefixAsync($"login:ai:{Identifiers.Hash(Identifiers.NormalizeEmail(email), 24)}:", ct);
    }
}

public interface IAbuseGuard
{
    /// <summary>Counts one use of a named limit for each identifier; throws a 429 AuthException when any is exceeded.</summary>
    Task EnforceAsync(string policy, RateLimitRule rule, CancellationToken ct, params string[] identifiers);
}

public sealed class AbuseGuard(IRateLimitStore store) : IAbuseGuard
{
    public async Task EnforceAsync(string policy, RateLimitRule rule, CancellationToken ct, params string[] identifiers)
    {
        var window = TimeSpan.FromSeconds(rule.WindowSeconds);
        var exceeded = false;
        foreach (var id in identifiers)
        {
            var n = await store.IncrementAsync($"rl:{policy}:{Identifiers.Hash(id, 24)}", window, ct);
            if (n > rule.Limit) exceeded = true;
        }

        if (exceeded)
            throw new AuthException(ResultKind.TooManyRequests, "Too many requests. Please try again later.") { RetryAfterSeconds = rule.WindowSeconds };
    }
}
