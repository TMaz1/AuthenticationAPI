using AuthenticationAPI.Data;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Utils;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Services.Token;

public interface ISessionService
{
    /// <summary>Creates access + refresh tokens for a user whose authentication has been fully completed.</summary>
    Task<AuthResponse> StartSessionAsync(User user, bool persistent, string amr, CancellationToken ct);
    /// <summary>Invalidates outstanding access tokens (stamp), refresh tokens and (optionally) trusted devices.</summary>
    Task RevokeAllSessionsAsync(int userId, string reason, bool includeTrustedDevices, CancellationToken ct);
    /// <summary>Invalidates outstanding access tokens only.</summary>
    Task RotateStampAsync(int userId, CancellationToken ct);
}

public sealed class SessionService(
    AuthDataContext context,
    ITokenService tokens,
    IRefreshTokenService refresh,
    ISessionValidator validator) : ISessionService
{
    public async Task<AuthResponse> StartSessionAsync(User user, bool persistent, string amr, CancellationToken ct)
    {
        var authTime = DateTime.UtcNow;
        user.LastLoginAt = authTime;
        var issued = refresh.Issue(user, persistent, authTime, amr);
        await context.SaveChangesAsync(ct);

        return new AuthResponse
        {
            User = UserMapper.MapToUserResponse(user),
            Token = tokens.CreateAccessToken(user, authTime, amr),
            RefreshToken = issued.RawToken,
            Mfa = new MfaInfo { RequiresMfa = false }
        };
    }

    public async Task RevokeAllSessionsAsync(int userId, string reason, bool includeTrustedDevices, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        await RotateStampAsync(userId, ct);
        await refresh.RevokeAllForUserAsync(userId, reason, ct);
        if (includeTrustedDevices)
        {
            await context.TrustedDevices
                .Where(d => d.UserId == userId && d.RevokedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(d => d.RevokedAt, now), ct);
        }
    }

    public async Task RotateStampAsync(int userId, CancellationToken ct)
    {
        var stamp = User.NewStamp();
        var now = DateTime.UtcNow;
        await context.Users.Where(u => u.Id == userId)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.SecurityStamp, stamp).SetProperty(u => u.UpdatedAt, now), ct);
        validator.Invalidate(userId);
    }
}
