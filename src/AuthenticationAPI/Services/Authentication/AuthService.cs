using AuthenticationAPI.Configuration;
using AuthenticationAPI.Data;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Enums;
using AuthenticationAPI.Services.Mfa;
using AuthenticationAPI.Services.Notifications;
using AuthenticationAPI.Services.Password;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Services.Token;
using AuthenticationAPI.Utils;
using AuthenticationAPI.Utils.Logger;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Authentication;

public class AuthService : IAuthService
{
    private const string GenericLoginFailure = "Incorrect email or password.";
    private const string GenericResetSent = "If an account exists for that email, a password reset link has been sent.";

    private readonly AuthDataContext _db;
    private readonly IPasswordService _passwords;
    private readonly JwtSettings _jwt;
    private readonly SecurityOptions _sec;
    private readonly ITokenService _tokens;
    private readonly IRefreshTokenService _refresh;
    private readonly ISessionService _sessions;
    private readonly ITrustedDeviceService _devices;
    private readonly ILoginThrottle _throttle;
    private readonly IAbuseGuard _abuse;
    private readonly ISecurityAudit _audit;
    private readonly INotificationOutbox _outbox;
    private readonly IAppLogger<AuthService> _logger;
    private readonly string _appLink;

    public AuthService(
        AuthDataContext db, IPasswordService passwords, IOptions<JwtSettings> jwt, IOptions<SecurityOptions> sec,
        IOptions<AppSettings> app, ITokenService tokens, IRefreshTokenService refresh, ISessionService sessions,
        ITrustedDeviceService devices, ILoginThrottle throttle, IAbuseGuard abuse, ISecurityAudit audit,
        INotificationOutbox outbox, IAppLogger<AuthService> logger)
    {
        _db = db; _passwords = passwords; _jwt = jwt.Value; _sec = sec.Value; _tokens = tokens; _refresh = refresh;
        _sessions = sessions; _devices = devices; _throttle = throttle; _abuse = abuse; _audit = audit;
        _outbox = outbox; _logger = logger;
        _appLink = string.IsNullOrWhiteSpace(app.Value.AppLink) ? "https://app.example.com" : app.Value.AppLink.Trim().TrimEnd('/');
    }

    private Task<ServiceResponse<T>> Run<T>(string op, Func<Task<ServiceResponse<T>>> action) =>
        ServiceGuard.RunAsync(action, ex => _logger.Error(ex, "{Operation} failed unexpectedly", op));

    public Task<ServiceResponse<bool>> Register(UserRegister request, string ip, CancellationToken ct = default) => Run("Register", async () =>
    {
        await _abuse.EnforceAsync("register", _sec.RateLimits.Register, ct, ip);

        var email = Identifiers.NormalizeEmail(request.Email);
        var problems = _passwords.Validate(request.Password, email);
        if (problems.Count > 0) throw new AuthException(ResultKind.BadRequest, string.Join(" ", problems));
        if (request.Password != request.ConfirmPassword) throw new AuthException(ResultKind.BadRequest, "'Password' and 'Confirm Password' do not match");
        if (!Enum.IsDefined(request.Role)) throw new AuthException(ResultKind.BadRequest, $"Invalid RoleType: {request.Role}");

        if (await _db.Users.AsNoTracking().AnyAsync(u => u.Email == email, ct))
            throw new AuthException(ResultKind.BadRequest, "Register with another email.");

        var h = _passwords.Hash(request.Password);
        var rawToken = TokenGenerator.NewOpaqueToken();
        var tokenHash = TokenHasher.Hash(rawToken);
        var now = DateTime.UtcNow;

        var user = new User
        {
            Username = request.Username,
            Email = email,
            PasswordHash = h.Hash,
            PasswordSalt = h.Salt,
            PasswordHashVersion = h.Version,
            PasswordHashIterations = h.Iterations,
            PasswordChangedAt = now,
            FirstName = request.FirstName,
            LastName = request.LastName,
            PhoneNumber = request.PhoneNumber,
            Role = RoleType.Viewer, // SECURITY: never trust a client-supplied role
            VerificationToken = tokenHash,
            VerificationTokenExpires = now.AddHours(_jwt.VerificationTokenExpiration)
        };
        _db.Users.Add(user);
        _outbox.Enqueue(NotificationTypes.Verification,
            new NotificationPayload(email, $"{_appLink}/verify-account?token={rawToken}", null, _jwt.VerificationTokenExpiration),
            $"verify:{tokenHash[..24]}");

        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            throw new AuthException(ResultKind.BadRequest, "Register with another email.");
        }

        if (request.Role != RoleType.Viewer)
            await _audit.AddAndSaveAsync(AuditEvents.RoleEscalationIgnored, user.Id, detail: $"requested={request.Role}", ct: ct);

        _logger.Info("User {User} registered", Identifiers.EmailId(email));
        return new ServiceResponse<bool> { Data = true, Message = $"Successfully registered user with email '{email}'" };
    });

    public Task<ServiceResponse<AuthResponse>> Login(UserLogin request, string ip, CancellationToken ct = default) => Run("Login", async () =>
    {
        var email = Identifiers.NormalizeEmail(request.Email);

        // An attempt is reserved atomically BEFORE the password is checked, so concurrent guesses cannot exceed the limit.
        if (!await _throttle.TryReserveAttemptAsync(email, ip, ct))
        {
            _logger.Warn("Login blocked by throttle for {User}", Identifiers.EmailId(email));
            AuthMetrics.LoginOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "throttled"));
            throw new AuthException(ResultKind.TooManyRequests, "Too many login attempts. Try again later.") { RetryAfterSeconds = _throttle.RetryAfterSeconds };
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user is null)
        {
            _passwords.VerifyDummy(request.Password); // equalise timing with the real-user path
            AuthMetrics.LoginOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "failed"));
            throw new AuthException(ResultKind.BadRequest, GenericLoginFailure);
        }

        var verification = _passwords.Verify(request.Password, user);
        if (!verification.Verified)
        {
            _logger.Warn("Invalid password for {User}", Identifiers.EmailId(email));
            AuthMetrics.LoginOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "failed"));
            throw new AuthException(ResultKind.BadRequest, GenericLoginFailure);
        }

        await _throttle.ReleaseAttemptAsync(email, ip, ct); // correct password: only failures should accumulate

        if (user.IsDisabled)
        {
            AuthMetrics.LoginOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "disabled"));
            throw new AuthException(ResultKind.Forbidden, "This account has been disabled.");
        }

        if (verification.NeedsUpgrade)
        {
            var h = _passwords.Hash(request.Password);
            user.PasswordHash = h.Hash; user.PasswordSalt = h.Salt;
            user.PasswordHashVersion = h.Version; user.PasswordHashIterations = h.Iterations;
            await _db.SaveChangesAsync(ct);
            _logger.Info("Password hash upgraded for {User}", Identifiers.EmailId(email));
        }

        // unverified: short-lived token reflecting the REAL (unverified) state, and no refresh token
        if (!user.IsActive)
        {
            AuthMetrics.LoginOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "unverified"));
            return new ServiceResponse<AuthResponse>
            {
                Data = new AuthResponse
                {
                    User = UserMapper.MapToUserResponse(user),
                    Token = _tokens.CreateAccessToken(user, DateTime.UtcNow, "pwd"),
                    RefreshToken = null,
                    Mfa = new MfaInfo { RequiresMfa = false }
                },
                Message = "Account not verified. Please verify or resend verification email."
            };
        }

        if (user.TwoFactorEnabled)
        {
            // A trusted device may replace the MFA step only. It never bypasses the password, disablement, or admin MFA.
            var trusted = await _devices.TryUseAsync(user, request.TrustedDeviceToken, ct);
            if (trusted.Trusted)
            {
                var session = await _sessions.StartSessionAsync(user, request.RememberMe, "pwd trusted_device", ct);
                session.TrustedDeviceToken = trusted.NewToken;
                AuthMetrics.LoginOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "success_trusted_device"));
                return new ServiceResponse<AuthResponse> { Data = session, Message = $"Successfully logged in user with email '{user.Email}'" };
            }

            var rawChallenge = TokenGenerator.NewOpaqueToken();
            var now = DateTime.UtcNow;
            _db.MfaChallenges.Add(new MfaChallenge
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                TokenHash = TokenHasher.Hash(rawChallenge),
                CreatedAt = now,
                ExpiresAt = now.AddMinutes(_sec.Mfa.ChallengeMinutes),
                RememberMe = request.RememberMe
            });
            await _db.SaveChangesAsync(ct);

            var methods = new List<MfaMethodType> { MfaMethodType.Totp };
            if (_sec.Mfa.EmailOtpEnabled) methods.Add(MfaMethodType.Email);
            if (_sec.Mfa.SmsEnabled && user.PhoneVerifiedAt is not null && !string.IsNullOrEmpty(user.PhoneNumber)) methods.Add(MfaMethodType.Sms);

            AuthMetrics.LoginOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "mfa_required"));
            return new ServiceResponse<AuthResponse>
            {
                Data = new AuthResponse
                {
                    User = UserMapper.MapToUserResponse(user),
                    Mfa = new MfaInfo { RequiresMfa = true, SelectedMethod = MfaMethodType.Totp, AvailableMethods = methods, ChallengeToken = rawChallenge }
                },
                Message = "MFA required. Please verify using your authenticator app."
            };
        }

        var auth = await _sessions.StartSessionAsync(user, request.RememberMe, "pwd", ct);
        AuthMetrics.LoginOutcome.Add(1, new KeyValuePair<string, object?>("outcome", "success"));
        _logger.Info("User {User} logged in", Identifiers.EmailId(email));
        return new ServiceResponse<AuthResponse> { Data = auth, Message = $"Successfully logged in user with email '{user.Email}'" };
    });

    public Task<ServiceResponse<AuthResponse>> GetUserData(int userId, CancellationToken ct = default) => Run("GetUserData", async () =>
    {
        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId, ct)
                   ?? throw new AuthException(ResultKind.NotFound, "User not found.");
        return new ServiceResponse<AuthResponse>
        {
            Data = new AuthResponse { User = UserMapper.MapToUserResponse(user), Mfa = new MfaInfo { RequiresMfa = user.TwoFactorEnabled } },
            Message = "User data retrieved successfully."
        };
    });

    public Task<ServiceResponse<bool>> VerifyAccount(string token, string ip, CancellationToken ct = default) => Run("VerifyAccount", async () =>
    {
        await _abuse.EnforceAsync("redeem", _sec.RateLimits.TokenRedemption, ct, ip);
        const string invalid = "Invalid or expired verification token.";
        if (!Identifiers.LooksLikeOpaqueToken(token)) throw new AuthException(ResultKind.BadRequest, invalid);

        var hash = TokenHasher.Hash(token);
        var now = DateTime.UtcNow;

        // Atomic single-use redemption: only one concurrent request can match the still-populated token.
        var rows = await _db.Users
            .Where(u => u.VerificationToken == hash && u.VerificationTokenExpires > now && !u.IsDisabled)
            .ExecuteUpdateAsync(s => s
                .SetProperty(u => u.IsActive, true)
                .SetProperty(u => u.VerifiedAt, (DateTime?)now)
                .SetProperty(u => u.VerificationToken, (string?)null)
                .SetProperty(u => u.VerificationTokenExpires, (DateTime?)null)
                .SetProperty(u => u.UpdatedAt, now), ct);

        if (rows != 1) throw new AuthException(ResultKind.BadRequest, invalid);
        return new ServiceResponse<bool> { Data = true, Message = "Account verified." };
    });

    public Task<ServiceResponse<bool>> ResendVerificationEmail(int userId, CancellationToken ct = default) => Run("ResendVerification", async () =>
    {
        await _abuse.EnforceAsync("resend", _sec.RateLimits.ResendVerification, ct, $"u:{userId}");

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct) ?? throw new AuthException(ResultKind.NotFound, "User not found.");
        if (user.IsActive || user.VerifiedAt != null) throw new AuthException(ResultKind.BadRequest, "Account already verified.");

        var raw = TokenGenerator.NewOpaqueToken();
        var hash = TokenHasher.Hash(raw);
        user.VerificationToken = hash;
        user.VerificationTokenExpires = DateTime.UtcNow.AddHours(_jwt.VerificationTokenExpiration);
        _outbox.Enqueue(NotificationTypes.Verification,
            new NotificationPayload(user.Email, $"{_appLink}/verify-account?token={raw}", null, _jwt.VerificationTokenExpiration),
            $"verify:{hash[..24]}");
        await _db.SaveChangesAsync(ct);

        return new ServiceResponse<bool> { Data = true, Message = "Verification email resent successfully." };
    });

    public Task<ServiceResponse<AuthResponse>> RefreshToken(string refreshToken, string ip, CancellationToken ct = default) => Run("RefreshToken", async () =>
    {
        await _abuse.EnforceAsync("refresh", _sec.RateLimits.Refresh, ct, ip);
        var r = await _refresh.RotateAsync(refreshToken, ct);
        return new ServiceResponse<AuthResponse>
        {
            Data = new AuthResponse
            {
                User = UserMapper.MapToUserResponse(r.User),
                Token = _tokens.CreateAccessToken(r.User, r.AuthTime, r.Amr),
                RefreshToken = r.Token.RawToken,
                Mfa = new MfaInfo { RequiresMfa = false }
            },
            Message = "Token refreshed successfully."
        };
    });

    public Task<ServiceResponse<bool>> Logout(int userId, CancellationToken ct = default) => Run("Logout", async () =>
    {
        // Revokes the user's refresh tokens. Already-issued access tokens stay valid until they expire (<= AccessTokenExpiration).
        await _refresh.RevokeAllForUserAsync(userId, "logout", ct);
        return new ServiceResponse<bool> { Data = true, Message = "Successfully logged out." };
    });

    public Task<ServiceResponse<bool>> RevokeAllSessions(int userId, CancellationToken ct = default) => Run("RevokeAllSessions", async () =>
    {
        await _sessions.RevokeAllSessionsAsync(userId, "revoke_all", includeTrustedDevices: true, ct);
        await _audit.AddAndSaveAsync(AuditEvents.SessionsRevoked, userId, userId, ct: ct);
        return new ServiceResponse<bool> { Data = true, Message = "All sessions and trusted devices were revoked." };
    });

    public Task<ServiceResponse<bool>> RequestPasswordReset(string email, string ip, CancellationToken ct = default) => Run("RequestPasswordReset", async () =>
    {
        await _abuse.EnforceAsync("pwreset-ip", _sec.RateLimits.PasswordResetPerIp, ct, ip);
        var norm = Identifiers.NormalizeEmail(email);

        try
        {
            await _abuse.EnforceAsync("pwreset-acct", _sec.RateLimits.PasswordResetPerAccount, ct, norm);
        }
        catch (AuthException ex) when (ex.Kind == ResultKind.TooManyRequests)
        {
            // Over the per-account limit: answer exactly like success so the limit cannot be used to probe accounts.
            return new ServiceResponse<bool> { Data = true, Message = GenericResetSent };
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == norm, ct);
        if (user is not null && !user.IsDisabled)
        {
            var raw = TokenGenerator.NewOpaqueToken();
            var hash = TokenHasher.Hash(raw);
            user.PasswordResetToken = hash;
            user.PasswordResetTokenExpires = DateTime.UtcNow.AddMinutes(_jwt.PasswordResetTokenExpiration);
            // NOTE: requesting a reset must NOT sign the user out; anyone can request one for any address.
            _outbox.Enqueue(NotificationTypes.PasswordReset,
                new NotificationPayload(user.Email, $"{_appLink}/reset-password?token={raw}", null, _jwt.PasswordResetTokenExpiration),
                $"reset:{hash[..24]}");
            _audit.Add(AuditEvents.PasswordResetRequested, user.Id);
            await _db.SaveChangesAsync(ct);
        }

        return new ServiceResponse<bool> { Data = true, Message = GenericResetSent };
    });

    public Task<ServiceResponse<bool>> ResetPassword(ResetPassword request, string ip, CancellationToken ct = default) => Run("ResetPassword", async () =>
    {
        await _abuse.EnforceAsync("redeem", _sec.RateLimits.TokenRedemption, ct, ip);
        const string invalid = "Invalid or expired reset token.";
        if (!Identifiers.LooksLikeOpaqueToken(request.Token)) throw new AuthException(ResultKind.BadRequest, invalid);

        var email = Identifiers.NormalizeEmail(request.Email);
        var problems = _passwords.Validate(request.NewPassword, email);
        if (problems.Count > 0) throw new AuthException(ResultKind.BadRequest, string.Join(" ", problems));
        if (request.NewPassword != request.ConfirmPassword) throw new AuthException(ResultKind.BadRequest, "Password and Confirm Password must match.");

        var tokenHash = TokenHasher.Hash(request.Token);
        var now = DateTime.UtcNow;

        // cheap pre-check so an attacker cannot make the server run PBKDF2 for arbitrary tokens
        var candidate = await _db.Users.AsNoTracking()
            .Where(u => u.PasswordResetToken == tokenHash && u.PasswordResetTokenExpires > now && u.Email == email)
            .Select(u => new { u.Id }).FirstOrDefaultAsync(ct);
        if (candidate is null) throw new AuthException(ResultKind.BadRequest, invalid);

        var h = _passwords.Hash(request.NewPassword);
        var stamp = User.NewStamp();
        var rows = await _db.Users
            .Where(u => u.Id == candidate.Id && u.PasswordResetToken == tokenHash && u.PasswordResetTokenExpires > now)
            .ExecuteUpdateAsync(s => s
                .SetProperty(u => u.PasswordHash, h.Hash)
                .SetProperty(u => u.PasswordSalt, h.Salt)
                .SetProperty(u => u.PasswordHashVersion, h.Version)
                .SetProperty(u => u.PasswordHashIterations, (int?)h.Iterations)
                .SetProperty(u => u.PasswordChangedAt, (DateTime?)now)
                .SetProperty(u => u.SecurityStamp, stamp)
                .SetProperty(u => u.PasswordResetToken, (string?)null)
                .SetProperty(u => u.PasswordResetTokenExpires, (DateTime?)null)
                .SetProperty(u => u.UpdatedAt, now), ct);
        if (rows != 1) throw new AuthException(ResultKind.BadRequest, invalid);

        // a successful reset ends every existing session and clears lockout; it does NOT log the user in
        await _sessions.RevokeAllSessionsAsync(candidate.Id, "password_reset", includeTrustedDevices: true, ct);
        await _throttle.UnlockAsync(email, ct);
        _audit.Add(AuditEvents.PasswordChanged, candidate.Id, detail: "reset");
        _outbox.Enqueue(NotificationTypes.PasswordChanged, new NotificationPayload(email));
        await _db.SaveChangesAsync(ct);

        return new ServiceResponse<bool> { Data = true, Message = "Password has been reset." };
    });

    public Task<ServiceResponse<bool>> UnlockUser(string email, int actorUserId, CancellationToken ct = default) => Run("UnlockUser", async () =>
    {
        var norm = Identifiers.NormalizeEmail(email);
        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == norm, ct) ?? throw new AuthException(ResultKind.NotFound, "User not found.");
        await _throttle.UnlockAsync(norm, ct);
        await _audit.AddAndSaveAsync(AuditEvents.AccountUnlocked, user.Id, actorUserId, ct: ct);
        return new ServiceResponse<bool> { Data = true, Message = $"User '{norm}' has been unlocked." };
    });

    public Task<ServiceResponse<bool>> SetUserDisabled(string email, bool disabled, int actorUserId, CancellationToken ct = default) => Run("SetUserDisabled", async () =>
    {
        var user = await FindForAdminAsync(email, actorUserId, ct);
        user.IsDisabled = disabled;
        if (disabled) user.SecurityStamp = User.NewStamp();
        _audit.Add(disabled ? AuditEvents.AccountDisabled : AuditEvents.AccountEnabled, user.Id, actorUserId);
        await _db.SaveChangesAsync(ct);

        if (disabled) await _sessions.RevokeAllSessionsAsync(user.Id, "account_disabled", includeTrustedDevices: true, ct);
        else await _sessions.RotateStampAsync(user.Id, ct); // also drops any cached "disabled" state

        return new ServiceResponse<bool> { Data = true, Message = disabled ? "Account disabled." : "Account enabled." };
    });

    public Task<ServiceResponse<bool>> SetRole(string email, RoleType role, int actorUserId, CancellationToken ct = default) => Run("SetRole", async () =>
    {
        if (!Enum.IsDefined(role)) throw new AuthException(ResultKind.BadRequest, "Invalid role.");
        var user = await FindForAdminAsync(email, actorUserId, ct);
        var previous = user.Role;
        user.Role = role;
        user.SecurityStamp = User.NewStamp(); // old access tokens carrying the previous role stop working
        _audit.Add(AuditEvents.RoleChanged, user.Id, actorUserId, $"{previous}->{role}");
        await _db.SaveChangesAsync(ct);
        await _sessions.RotateStampAsync(user.Id, ct);

        return new ServiceResponse<bool> { Data = true, Message = $"Role changed to {role}." };
    });

    private async Task<User> FindForAdminAsync(string email, int actorUserId, CancellationToken ct)
    {
        var norm = Identifiers.NormalizeEmail(email);
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == norm, ct) ?? throw new AuthException(ResultKind.NotFound, "User not found.");
        if (user.Id == actorUserId) throw new AuthException(ResultKind.BadRequest, "Administrators cannot change their own role or disable their own account.");
        return user;
    }

    private static bool IsUniqueViolation(DbUpdateException ex) =>
        ex.InnerException is SqlException { Number: 2601 or 2627 };
}
