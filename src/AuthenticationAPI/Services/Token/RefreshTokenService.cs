using AuthenticationAPI.Configuration;
using AuthenticationAPI.Data;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Utils.Logger;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Token;

public sealed record IssuedRefreshToken(string RawToken, DateTime ExpiresAt, Guid FamilyId);
public sealed record RotationResult(User User, IssuedRefreshToken Token, DateTime AuthTime, string Amr);

public interface IRefreshTokenService
{
    /// <summary>Creates a new family's first token. Added to the current unit of work; caller must SaveChanges.</summary>
    IssuedRefreshToken Issue(User user, bool persistent, DateTime authTimeUtc, string amr, Guid? familyId = null);
    /// <summary>Single-use exchange with reuse detection. Throws AuthException on any failure.</summary>
    Task<RotationResult> RotateAsync(string rawToken, CancellationToken ct = default);
    Task RevokeAllForUserAsync(int userId, string reason, CancellationToken ct = default);
}

public sealed class RefreshTokenService(
    AuthDataContext context,
    IOptions<JwtSettings> jwt,
    IOptions<SecurityOptions> security,
    ISecurityAudit audit,
    IAppLogger<RefreshTokenService> logger) : IRefreshTokenService
{
    private const string Invalid = "Invalid or expired refresh token.";
    private readonly JwtSettings _jwt = jwt.Value;
    private readonly SecurityOptions _sec = security.Value;

    public IssuedRefreshToken Issue(User user, bool persistent, DateTime authTimeUtc, string amr, Guid? familyId = null)
    {
        var now = DateTime.UtcNow;
        var lifetime = TimeSpan.FromDays(persistent ? _jwt.RememberMeRefreshTokenExpiration : _jwt.RefreshTokenExpiration);
        var absoluteCap = authTimeUtc.AddDays(_sec.MaxSessionDays);
        var expires = now + lifetime;
        if (expires > absoluteCap) expires = absoluteCap;

        var raw = TokenGenerator.NewOpaqueToken();
        var family = familyId ?? Guid.NewGuid();
        context.RefreshTokens.Add(new RefreshTokenRecord
        {
            UserId = user.Id,
            FamilyId = family,
            TokenHash = TokenHasher.Hash(raw),
            CreatedAt = now,
            ExpiresAt = expires,
            AuthTime = authTimeUtc,
            Amr = amr,
            Persistent = persistent
        });
        return new IssuedRefreshToken(raw, expires, family);
    }

    public async Task<RotationResult> RotateAsync(string rawToken, CancellationToken ct = default)
    {
        if (!Identifiers.LooksLikeOpaqueToken(rawToken)) throw new AuthException(ResultKind.BadRequest, Invalid);

        var hash = TokenHasher.Hash(rawToken);
        var record = await context.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(r => r.TokenHash == hash, ct)
                     ?? throw new AuthException(ResultKind.BadRequest, Invalid);
        var now = DateTime.UtcNow;

        if (record.RevokedAt is not null)
        {
            AuthMetrics.RefreshOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "revoked"));
            throw new AuthException(ResultKind.BadRequest, Invalid);
        }

        if (record.ConsumedAt is not null)
        {
            await HandleReuseAsync(record, ct);
            throw new AuthException(ResultKind.BadRequest, Invalid);
        }

        // expired, or the session as a whole has outlived its absolute cap (rotation never extends past AuthTime + MaxSessionDays)
        if (record.ExpiresAt <= now || record.AuthTime.AddDays(_sec.MaxSessionDays) <= now) throw new AuthException(ResultKind.BadRequest, Invalid);

        await using var tx = await context.Database.BeginTransactionAsync(ct);

        // Atomic single-use consumption: of N concurrent requests presenting this token, exactly one updates a row.
        var consumed = await context.RefreshTokens
            .Where(r => r.Id == record.Id && r.ConsumedAt == null && r.RevokedAt == null && r.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.ConsumedAt, now), ct);

        if (consumed != 1)
        {
            await tx.RollbackAsync(ct);
            // we lost a race: the token was consumed (or revoked) a moment ago by another request -> treat as replay
            var current = await context.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(r => r.Id == record.Id, ct);
            if (current?.ConsumedAt is not null && current.RevokedAt is null) await HandleReuseAsync(current, ct);
            throw new AuthException(ResultKind.BadRequest, Invalid);
        }

        var user = await context.Users.FirstOrDefaultAsync(u => u.Id == record.UserId, ct);
        if (user is null || user.IsDisabled)
        {
            await context.RefreshTokens
                .Where(r => r.FamilyId == record.FamilyId && r.RevokedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(r => r.RevokedAt, now).SetProperty(r => r.RevokedReason, "account_disabled"), ct);
            await tx.CommitAsync(ct);
            throw new AuthException(ResultKind.BadRequest, Invalid);
        }

        if (!user.IsActive)
        {
            await tx.RollbackAsync(ct);
            throw new AuthException(ResultKind.BadRequest, "User must verify their account before refreshing token.");
        }

        var next = Issue(user, record.Persistent, record.AuthTime, record.Amr, record.FamilyId);
        await context.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        AuthMetrics.RefreshOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "rotated"));
        return new RotationResult(user, next, record.AuthTime, record.Amr);
    }

    private async Task HandleReuseAsync(RefreshTokenRecord record, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var revoked = await context.RefreshTokens
            .Where(r => r.FamilyId == record.FamilyId && r.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.RevokedAt, now).SetProperty(r => r.RevokedReason, "reuse_detected"), ct);

        AuthMetrics.RefreshOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "reuse_detected"));
        logger.Warn("Refresh token reuse detected; family revoked (user {UserId}, tokens revoked {Count})", record.UserId, revoked);
        await audit.AddAndSaveAsync(AuditEvents.RefreshReuseDetected, record.UserId, detail: $"family={record.FamilyId:N}", ct: ct);
    }

    public async Task RevokeAllForUserAsync(int userId, string reason, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        await context.RefreshTokens
            .Where(r => r.UserId == userId && r.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.RevokedAt, now).SetProperty(r => r.RevokedReason, reason), ct);
    }
}
