using AuthenticationAPI.Configuration;
using AuthenticationAPI.Data;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Enums;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Utils.Logger;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Mfa;

public sealed record TrustedDeviceUse(bool Trusted, string? NewToken);

public interface ITrustedDeviceService
{
    /// <summary>Creates a device credential after a successful MFA step. Returns null when the feature is off or the user is an administrator.</summary>
    Task<string?> CreateAsync(User user, string? label, CancellationToken ct);
    /// <summary>Validates and rotates a presented credential. A previously rotated (replayed) credential revokes the device.</summary>
    Task<TrustedDeviceUse> TryUseAsync(User user, string? rawToken, CancellationToken ct);
    Task<List<TrustedDeviceInfo>> ListAsync(int userId, CancellationToken ct);
    Task<bool> RevokeAsync(int userId, Guid deviceId, CancellationToken ct);
}

public sealed class TrustedDeviceService(
    AuthDataContext db,
    IOptions<SecurityOptions> options,
    ISecurityAudit audit,
    IAppLogger<TrustedDeviceService> logger) : ITrustedDeviceService
{
    private static readonly TrustedDeviceUse No = new(false, null);
    private readonly TrustedDeviceOptions _o = options.Value.TrustedDevices;

    public async Task<string?> CreateAsync(User user, string? label, CancellationToken ct)
    {
        if (!_o.Enabled || user.Role == RoleType.Administrator) return null;

        var now = DateTime.UtcNow;
        var active = await db.TrustedDevices
            .Where(d => d.UserId == user.Id && d.RevokedAt == null && d.ExpiresAt > now)
            .OrderByDescending(d => d.CreatedAt).Select(d => d.Id).ToListAsync(ct);
        var surplus = active.Skip(Math.Max(_o.MaxPerUser - 1, 0)).ToList();
        if (surplus.Count > 0)
            await db.TrustedDevices.Where(d => surplus.Contains(d.Id)).ExecuteUpdateAsync(s => s.SetProperty(d => d.RevokedAt, now), ct);

        var raw = TokenGenerator.NewOpaqueToken();
        var device = new TrustedDevice
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = TokenHasher.Hash(raw),
            Label = SanitizeLabel(label),
            CreatedAt = now,
            ExpiresAt = now.AddDays(_o.Days)
        };
        db.TrustedDevices.Add(device);
        audit.Add(AuditEvents.TrustedDeviceCreated, user.Id, user.Id);
        await db.SaveChangesAsync(ct);
        return raw;
    }

    public async Task<TrustedDeviceUse> TryUseAsync(User user, string? rawToken, CancellationToken ct)
    {
        if (!_o.Enabled || user.Role == RoleType.Administrator || !Identifiers.LooksLikeOpaqueToken(rawToken)) return No;

        var hash = TokenHasher.Hash(rawToken!);
        var now = DateTime.UtcNow;
        var device = await db.TrustedDevices.AsNoTracking()
            .FirstOrDefaultAsync(d => d.TokenHash == hash || d.PreviousTokenHash == hash, ct);

        // unknown, or presented for a different user than it was issued to
        if (device is null || device.UserId != user.Id) return No;
        if (device.RevokedAt is not null || device.ExpiresAt <= now) return No;

        if (device.TokenHash != hash)
        {
            // an already-rotated credential was presented: a copy exists somewhere -> revoke the device
            await db.TrustedDevices.Where(d => d.Id == device.Id && d.RevokedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(d => d.RevokedAt, now), ct);
            logger.Warn("Replay of a rotated trusted-device credential detected for user {UserId}", user.Id);
            await audit.AddAndSaveAsync(AuditEvents.TrustedDeviceReplay, user.Id, detail: $"device={device.Id:N}", ct: ct);
            return No;
        }

        var newRaw = TokenGenerator.NewOpaqueToken();
        var newHash = TokenHasher.Hash(newRaw);
        var rows = await db.TrustedDevices
            .Where(d => d.Id == device.Id && d.TokenHash == hash && d.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(d => d.PreviousTokenHash, hash)
                .SetProperty(d => d.TokenHash, newHash)
                .SetProperty(d => d.LastUsedAt, (DateTime?)now), ct);

        return rows == 1 ? new TrustedDeviceUse(true, newRaw) : No;
    }

    public Task<List<TrustedDeviceInfo>> ListAsync(int userId, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        return db.TrustedDevices.AsNoTracking()
            .Where(d => d.UserId == userId && d.RevokedAt == null && d.ExpiresAt > now)
            .OrderByDescending(d => d.CreatedAt)
            .Select(d => new TrustedDeviceInfo { Id = d.Id, Label = d.Label, CreatedAt = d.CreatedAt, LastUsedAt = d.LastUsedAt, ExpiresAt = d.ExpiresAt })
            .ToListAsync(ct);
    }

    public async Task<bool> RevokeAsync(int userId, Guid deviceId, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        // scoped to the owner: one user can never revoke (or learn about) another user's device
        var rows = await db.TrustedDevices.Where(d => d.Id == deviceId && d.UserId == userId && d.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(d => d.RevokedAt, now), ct);
        if (rows == 1) await audit.AddAndSaveAsync(AuditEvents.TrustedDeviceRevoked, userId, userId, $"device={deviceId:N}", ct);
        return rows == 1;
    }

    private static string? SanitizeLabel(string? label)
    {
        if (string.IsNullOrWhiteSpace(label)) return null;
        var cleaned = new string(label.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return cleaned.Length == 0 ? null : cleaned.Length > 64 ? cleaned[..64] : cleaned;
    }
}
