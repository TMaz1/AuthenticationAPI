using AuthenticationAPI.Configuration;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Utils.Logger;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Security;

public static class AuditEvents
{
    public const string LoginLockout = "login.lockout";
    public const string LoginFailed = "login.failed";
    public const string PasswordChanged = "password.changed";
    public const string PasswordResetRequested = "password.reset_requested";
    public const string RefreshReuseDetected = "refresh.reuse_detected";
    public const string MfaEnabled = "mfa.enabled";
    public const string MfaDisabled = "mfa.disabled";
    public const string MfaAdminReset = "mfa.admin_reset";
    public const string MfaChallengeExhausted = "mfa.challenge_exhausted";
    public const string PhoneVerified = "phone.verified";
    public const string RoleChanged = "admin.role_changed";
    public const string RoleEscalationIgnored = "register.role_ignored";
    public const string AccountDisabled = "admin.account_disabled";
    public const string AccountEnabled = "admin.account_enabled";
    public const string AccountUnlocked = "admin.account_unlocked";
    public const string SessionsRevoked = "sessions.revoked";
    public const string TrustedDeviceCreated = "device.trusted";
    public const string TrustedDeviceRevoked = "device.revoked";
    public const string TrustedDeviceReplay = "device.replay_detected";
}

public interface ISecurityAudit
{
    /// <summary>Adds an event to the current unit of work; it is persisted by the caller's next SaveChangesAsync.</summary>
    void Add(string eventType, int? userId, int? actorUserId = null, string? detail = null);
    Task AddAndSaveAsync(string eventType, int? userId, int? actorUserId = null, string? detail = null, CancellationToken ct = default);
}

public sealed class SecurityAudit(AuthDataContext context, IAppLogger<SecurityAudit> logger) : ISecurityAudit
{
    public void Add(string eventType, int? userId, int? actorUserId = null, string? detail = null)
    {
        context.SecurityEvents.Add(new SecurityEvent
        {
            OccurredAt = DateTime.UtcNow,
            UserId = userId,
            ActorUserId = actorUserId,
            EventType = eventType,
            Detail = detail is { Length: > 256 } ? detail[..256] : detail
        });
        logger.Warn("SecurityEvent {EventType} user={UserId} actor={ActorUserId}", eventType, userId ?? 0, actorUserId ?? 0);
    }

    public async Task AddAndSaveAsync(string eventType, int? userId, int? actorUserId = null, string? detail = null, CancellationToken ct = default)
    {
        Add(eventType, userId, actorUserId, detail);
        await context.SaveChangesAsync(ct);
    }
}

public sealed record SessionState(string SecurityStamp, bool IsDisabled, int Role);

public interface ISessionValidator
{
    /// <summary>True only if the user still exists, is not disabled, and the token's security stamp is current.</summary>
    Task<bool> IsValidAsync(int userId, string? stampClaim, CancellationToken ct = default);
    void Invalidate(int userId);
}

/// <summary>
/// Makes revocation actually affect already-issued JWTs: every authenticated request compares the token's "sstamp"
/// with the user's current SecurityStamp. SQL Server is the source of truth; a short per-instance cache bounds the cost.
/// Staleness bound = Security:SessionCacheSeconds on instances that did not perform the change (0 disables caching).
/// </summary>
public sealed class SessionValidator(IServiceScopeFactory scopes, IMemoryCache cache, IOptions<SecurityOptions> options) : ISessionValidator
{
    private static string Key(int userId) => "sess:" + userId;

    public async Task<bool> IsValidAsync(int userId, string? stampClaim, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(stampClaim)) return false; // fail closed: tokens without a stamp are not accepted

        var ttl = options.Value.SessionCacheSeconds;
        SessionState? state = null;
        if (ttl > 0) cache.TryGetValue(Key(userId), out state);

        if (state is null)
        {
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AuthDataContext>();
            state = await db.Users.AsNoTracking()
                .Where(u => u.Id == userId)
                .Select(u => new SessionState(u.SecurityStamp, u.IsDisabled, (int)u.Role))
                .FirstOrDefaultAsync(ct);
            if (state is null) return false;
            if (ttl > 0) cache.Set(Key(userId), state, TimeSpan.FromSeconds(ttl));
        }

        return !state.IsDisabled && TokenHasher.FixedTimeEquals(state.SecurityStamp, stampClaim);
    }

    public void Invalidate(int userId) => cache.Remove(Key(userId));
}
