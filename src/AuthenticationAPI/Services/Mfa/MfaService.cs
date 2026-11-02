using AuthenticationAPI.Configuration;
using AuthenticationAPI.Data;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Enums;
using AuthenticationAPI.Services.Notifications;
using AuthenticationAPI.Services.Password;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Services.Token;
using AuthenticationAPI.Utils.Logger;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OtpNet;
using QRCoder;

namespace AuthenticationAPI.Services.Mfa;

public class MfaService : IMfaService
{
    private const string SecretPurpose = "mfa-secret";
    private const string GenericMfaFailure = "Invalid or expired verification.";

    private readonly AuthDataContext _db;
    private readonly IPasswordService _passwords;
    private readonly ISecretProtector _protector;
    private readonly SecurityOptions _sec;
    private readonly ISessionService _sessions;
    private readonly ITrustedDeviceService _devices;
    private readonly IAbuseGuard _abuse;
    private readonly ISecurityAudit _audit;
    private readonly INotificationOutbox _outbox;
    private readonly IAppLogger<MfaService> _logger;
    private readonly string _issuer;

    public MfaService(
        AuthDataContext db, IPasswordService passwords, ISecretProtector protector, IOptions<SecurityOptions> sec,
        IOptions<AppSettings> app, ISessionService sessions, ITrustedDeviceService devices, IAbuseGuard abuse,
        ISecurityAudit audit, INotificationOutbox outbox, IAppLogger<MfaService> logger)
    {
        _db = db; _passwords = passwords; _protector = protector; _sec = sec.Value; _sessions = sessions;
        _devices = devices; _abuse = abuse; _audit = audit; _outbox = outbox; _logger = logger;
        _issuer = string.IsNullOrWhiteSpace(app.Value.AppName) ? "AuthApp" : app.Value.AppName;
    }

    private Task<ServiceResponse<T>> Run<T>(string op, Func<Task<ServiceResponse<T>>> action) =>
        ServiceGuard.RunAsync(action, ex => _logger.Error(ex, "{Operation} failed unexpectedly", op));

    // ---- enrolment ------------------------------------------------------------------------------------------

    public Task<ServiceResponse<string>> SetupMfa(int userId, bool forceMfaRegenerate, CancellationToken ct = default) => Run("SetupMfa", async () =>
    {
        var user = await LoadUserAsync(userId, ct);
        if (user.TwoFactorEnabled) throw new AuthException(ResultKind.BadRequest, "MFA is already enabled. Disable it before re-setup.");

        var now = DateTime.UtcNow;
        string? secret = null;
        if (!forceMfaRegenerate && user.PendingMfaSecret is not null && user.PendingMfaSecretExpires > now)
            secret = _protector.Unprotect(user.PendingMfaSecret, SecretPurpose);

        if (secret is null)
        {
            secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
            user.PendingMfaSecret = _protector.Protect(secret, SecretPurpose);
            user.PendingMfaSecretExpires = now.AddMinutes(_sec.Mfa.PendingSetupMinutes);
            await _db.SaveChangesAsync(ct);
        }

        var uri = $"otpauth://totp/{Uri.EscapeDataString(_issuer)}:{Uri.EscapeDataString(user.Email)}?secret={secret}&issuer={Uri.EscapeDataString(_issuer)}&algorithm=SHA1&digits=6&period=30";
        string qr;
        using (var generator = new QRCodeGenerator())
        {
            var data = generator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
            using var code = new Base64QRCode(data);
            qr = code.GetGraphic(20);
        }

        return new ServiceResponse<string> { Data = qr, Message = "MFA setup generated successfully. Scan this QR code in your authenticator app." };
    });

    public Task<ServiceResponse<bool>> EnableMfa(int userId, OtpRequest request, CancellationToken ct = default) => Run("EnableMfa", async () =>
    {
        var user = await LoadUserAsync(userId, ct);
        if (user.TwoFactorEnabled) throw new AuthException(ResultKind.BadRequest, "MFA is already enabled. Disable it before re-setup.");

        // re-authentication: a stolen access token alone must not be able to attach an attacker's authenticator
        await RequirePasswordAsync(user, request.Password, ct);

        var now = DateTime.UtcNow;
        if (user.PendingMfaSecret is null || user.PendingMfaSecretExpires <= now)
            throw new AuthException(ResultKind.BadRequest, "No MFA setup found or expired.");

        var pending = user.PendingMfaSecret;
        var secret = _protector.Unprotect(pending, SecretPurpose);
        if (!Identifiers.IsSixDigitCode(request.OtpCode) || !new Totp(Base32Encoding.ToBytes(secret)).VerifyTotp(request.OtpCode, out long step, VerificationWindow.RfcSpecifiedNetworkDelay))
            throw new AuthException(ResultKind.BadRequest, "Invalid OTP code.");

        var rows = await _db.Users
            .Where(u => u.Id == userId && !u.TwoFactorEnabled && u.PendingMfaSecret == pending)
            .ExecuteUpdateAsync(s => s
                .SetProperty(u => u.TwoFactorEnabled, true)
                .SetProperty(u => u.MfaSecretKey, pending)
                .SetProperty(u => u.PendingMfaSecret, (string?)null)
                .SetProperty(u => u.PendingMfaSecretExpires, (DateTime?)null)
                .SetProperty(u => u.LastTotpStep, (long?)step)
                .SetProperty(u => u.LastTwoFactorAt, (DateTime?)now)
                .SetProperty(u => u.UpdatedAt, now), ct);
        if (rows != 1) throw new AuthException(ResultKind.BadRequest, "MFA could not be enabled. Start the setup again.");

        await _audit.AddAndSaveAsync(AuditEvents.MfaEnabled, userId, userId, ct: ct);
        return new ServiceResponse<bool> { Data = true, Message = "MFA enabled successfully." };
    });

    // ---- login completion -----------------------------------------------------------------------------------

    public Task<ServiceResponse<AuthResponse>> VerifyMfa(MfaVerifyRequest request, string ip, CancellationToken ct = default) => Run("VerifyMfa", async () =>
    {
        await _abuse.EnforceAsync("mfa-verify-ip", _sec.RateLimits.MfaVerifyPerIp, ct, ip);

        if (!Identifiers.LooksLikeOpaqueToken(request.ChallengeToken) || !Identifiers.IsSixDigitCode(request.Otp) || !IsMethodAllowed(request.Method))
            throw new AuthException(ResultKind.BadRequest, GenericMfaFailure);

        var now = DateTime.UtcNow;
        var email = Identifiers.NormalizeEmail(request.Email);
        var challengeHash = TokenHasher.Hash(request.ChallengeToken);

        var challenge = await _db.MfaChallenges.AsNoTracking().FirstOrDefaultAsync(c => c.TokenHash == challengeHash, ct);
        if (challenge is null || challenge.ConsumedAt is not null || challenge.ExpiresAt <= now)
            throw new AuthException(ResultKind.BadRequest, GenericMfaFailure);

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == challenge.UserId, ct);
        if (user is null || !string.Equals(user.Email, email, StringComparison.OrdinalIgnoreCase))
            throw new AuthException(ResultKind.BadRequest, GenericMfaFailure); // the challenge is bound to one account

        // Atomically reserve one attempt on this challenge. Concurrent guesses cannot exceed the limit.
        var max = _sec.Mfa.ChallengeMaxAttempts;
        var reserved = await _db.MfaChallenges
            .Where(c => c.Id == challenge.Id && c.ConsumedAt == null && c.ExpiresAt > now && c.Attempts < max)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.Attempts, c => c.Attempts + 1), ct);
        if (reserved != 1)
        {
            if (challenge.Attempts >= max) await _audit.AddAndSaveAsync(AuditEvents.MfaChallengeExhausted, user.Id, ct: ct);
            throw new AuthException(ResultKind.TooManyRequests, "Too many incorrect codes. Please sign in again.");
        }

        bool valid = request.Method switch
        {
            MfaMethodType.Totp => await VerifyAndConsumeTotpAsync(user, request.Otp, ct),
            MfaMethodType.Email or MfaMethodType.Sms => CheckOtp(challenge, request.Method, request.Otp, now),
            _ => false
        };

        if (!valid)
        {
            _logger.Warn("Invalid MFA code for {User}", Identifiers.EmailId(email));
            throw new AuthException(ResultKind.BadRequest, "Invalid or expired verification code.");
        }

        if (!user.TwoFactorEnabled || user.IsDisabled || !user.IsActive) throw new AuthException(ResultKind.BadRequest, GenericMfaFailure);

        // single use: exactly one concurrent verification may consume the challenge
        var consumed = await _db.MfaChallenges
            .Where(c => c.Id == challenge.Id && c.ConsumedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.ConsumedAt, (DateTime?)now), ct);
        if (consumed != 1) throw new AuthException(ResultKind.BadRequest, GenericMfaFailure);

        user.LastTwoFactorAt = now;
        var auth = await _sessions.StartSessionAsync(user, challenge.RememberMe, "pwd mfa", ct);
        if (request.TrustThisDevice) auth.TrustedDeviceToken = await _devices.CreateAsync(user, request.DeviceLabel, ct);

        return new ServiceResponse<AuthResponse> { Data = auth, Message = "MFA verification successful." };
    });

    public Task<ServiceResponse<bool>> SendOtp(MfaSendOtpRequest request, MfaMethodType method, string ip, CancellationToken ct = default) => Run("SendOtp", async () =>
    {
        if (method is not (MfaMethodType.Email or MfaMethodType.Sms) || !IsMethodAllowed(method))
            throw new AuthException(ResultKind.BadRequest, "This verification method is not available.");

        if (!Identifiers.LooksLikeOpaqueToken(request.ChallengeToken)) throw new AuthException(ResultKind.BadRequest, GenericMfaFailure);
        await _abuse.EnforceAsync("mfa-send", _sec.RateLimits.MfaSend, ct, ip, request.ChallengeToken);

        var now = DateTime.UtcNow;
        var email = Identifiers.NormalizeEmail(request.Email);
        var hash = TokenHasher.Hash(request.ChallengeToken);
        var challenge = await _db.MfaChallenges.AsNoTracking().FirstOrDefaultAsync(c => c.TokenHash == hash, ct);
        if (challenge is null || challenge.ConsumedAt is not null || challenge.ExpiresAt <= now)
            throw new AuthException(ResultKind.BadRequest, GenericMfaFailure);

        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == challenge.UserId, ct);
        if (user is null || !user.TwoFactorEnabled || user.IsDisabled || !string.Equals(user.Email, email, StringComparison.OrdinalIgnoreCase))
            throw new AuthException(ResultKind.BadRequest, GenericMfaFailure);

        string destination;
        if (method == MfaMethodType.Sms)
        {
            if (user.PhoneVerifiedAt is null || string.IsNullOrEmpty(user.PhoneNumber))
                throw new AuthException(ResultKind.BadRequest, "This verification method is not available.");
            destination = user.PhoneNumber;
        }
        else
        {
            destination = user.Email;
        }

        var code = TokenGenerator.NewSixDigitCode();
        var codeHash = _protector.KeyedHash("mfa-otp:" + challenge.Id.ToString("N"), code);
        var cooldownCutoff = now.AddSeconds(-_sec.Mfa.OtpResendCooldownSeconds);

        // Outbox row and OTP state commit together; the conditional update enforces the resend cooldown atomically.
        await using var tx = await _db.Database.BeginTransactionAsync(ct);
        var updated = await _db.MfaChallenges
            .Where(c => c.Id == challenge.Id && c.ConsumedAt == null && (c.OtpSentAt == null || c.OtpSentAt <= cooldownCutoff))
            .ExecuteUpdateAsync(s => s
                .SetProperty(c => c.OtpHash, codeHash)
                .SetProperty(c => c.OtpMethod, (MfaMethodType?)method)
                .SetProperty(c => c.OtpExpiresAt, (DateTime?)now.AddMinutes(_sec.Mfa.OtpMinutes))
                .SetProperty(c => c.OtpSentAt, (DateTime?)now), ct);
        if (updated != 1)
        {
            await tx.RollbackAsync(ct);
            throw new AuthException(ResultKind.TooManyRequests, "Please wait before requesting another code.") { RetryAfterSeconds = _sec.Mfa.OtpResendCooldownSeconds };
        }

        _outbox.Enqueue(method == MfaMethodType.Sms ? NotificationTypes.SmsCode : NotificationTypes.MfaCode,
            new NotificationPayload(destination, null, code, _sec.Mfa.OtpMinutes));
        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        return new ServiceResponse<bool> { Data = true, Message = method == MfaMethodType.Sms ? "OTP sent by SMS." : "OTP sent to your email." };
    });

    // ---- disabling / reset ----------------------------------------------------------------------------------

    public Task<ServiceResponse<bool>> DisableMfa(int userId, DisableMfaRequest request, CancellationToken ct = default) => Run("DisableMfa", async () =>
    {
        var user = await LoadUserAsync(userId, ct);
        if (!user.TwoFactorEnabled) throw new AuthException(ResultKind.BadRequest, "MFA is not enabled.");
        if (user.Role == RoleType.Administrator && _sec.Mfa.RequireMfaForAdministrators)
            throw new AuthException(ResultKind.Forbidden, "Administrators must keep MFA enabled.");

        // re-authentication with BOTH factors before weakening the account
        await RequirePasswordAsync(user, request.Password, ct);
        if (!await VerifyAndConsumeTotpAsync(user, request.OtpCode, ct))
            throw new AuthException(ResultKind.BadRequest, "Invalid authenticator code.");

        await ClearMfaAsync(user, userId, AuditEvents.MfaDisabled, ct);
        return new ServiceResponse<bool> { Data = true, Message = "Two-factor authentication disabled." };
    });

    public Task<ServiceResponse<bool>> ResetMfaAdmin(string email, int actorUserId, CancellationToken ct = default) => Run("ResetMfaAdmin", async () =>
    {
        var norm = Identifiers.NormalizeEmail(email);
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == norm, ct) ?? throw new AuthException(ResultKind.NotFound, "User not found.");
        if (user.Id == actorUserId) throw new AuthException(ResultKind.BadRequest, "Use the disable endpoint to change your own MFA.");

        await ClearMfaAsync(user, actorUserId, AuditEvents.MfaAdminReset, ct);
        return new ServiceResponse<bool> { Data = true, Message = $"MFA reset by admin for {norm}." };
    });

    private async Task ClearMfaAsync(User user, int actorId, string auditEvent, CancellationToken ct)
    {
        user.TwoFactorEnabled = false;
        user.MfaSecretKey = null;
        user.LastTwoFactorAt = null;
        user.LastTotpStep = null;
        user.PendingMfaSecret = null;
        user.PendingMfaSecretExpires = null;
        user.SecurityStamp = User.NewStamp();
        _audit.Add(auditEvent, user.Id, actorId);
        _outbox.Enqueue(NotificationTypes.MfaDisabled, new NotificationPayload(user.Email));
        await _db.SaveChangesAsync(ct);

        // weakening an account ends every session and trusted device
        await _sessions.RevokeAllSessionsAsync(user.Id, "mfa_changed", includeTrustedDevices: true, ct);
    }

    // ---- SMS phone enrolment --------------------------------------------------------------------------------

    public Task<ServiceResponse<bool>> EnrollPhone(int userId, SmsEnrollRequest request, CancellationToken ct = default) => Run("EnrollPhone", async () =>
    {
        if (!_sec.Mfa.SmsEnabled) throw new AuthException(ResultKind.NotFound, "SMS verification is not enabled.");
        if (!Identifiers.IsE164(request.PhoneNumber)) throw new AuthException(ResultKind.BadRequest, "Phone number must be in E.164 format, e.g. +14155550123.");

        var user = await LoadUserAsync(userId, ct);
        await _abuse.EnforceAsync("mfa-send", _sec.RateLimits.MfaSend, ct, $"u:{userId}");
        await RequirePasswordAsync(user, request.Password, ct);

        // changing the phone number of an MFA-protected account also requires a current authenticator code
        if (user.TwoFactorEnabled && (request.OtpCode is null || !await VerifyAndConsumeTotpAsync(user, request.OtpCode, ct)))
            throw new AuthException(ResultKind.BadRequest, "A valid authenticator code is required.");

        var code = TokenGenerator.NewSixDigitCode();
        user.PendingPhoneNumber = request.PhoneNumber;
        user.PendingPhoneCodeHash = _protector.KeyedHash($"phone:{userId}", code);
        user.PendingPhoneCodeExpires = DateTime.UtcNow.AddMinutes(_sec.Mfa.PhoneCodeMinutes);
        user.PendingPhoneAttempts = 0;
        _outbox.Enqueue(NotificationTypes.SmsCode, new NotificationPayload(request.PhoneNumber, null, code, _sec.Mfa.PhoneCodeMinutes));
        await _db.SaveChangesAsync(ct);

        return new ServiceResponse<bool> { Data = true, Message = "Verification code sent." };
    });

    public Task<ServiceResponse<bool>> ConfirmPhone(int userId, string code, CancellationToken ct = default) => Run("ConfirmPhone", async () =>
    {
        if (!_sec.Mfa.SmsEnabled) throw new AuthException(ResultKind.NotFound, "SMS verification is not enabled.");
        const string invalid = "Invalid or expired verification code.";
        if (!Identifiers.IsSixDigitCode(code)) throw new AuthException(ResultKind.BadRequest, invalid);

        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId, ct) ?? throw new AuthException(ResultKind.NotFound, "User not found.");
        var now = DateTime.UtcNow;
        if (user.PendingPhoneNumber is null || user.PendingPhoneCodeHash is null || user.PendingPhoneCodeExpires <= now)
            throw new AuthException(ResultKind.BadRequest, invalid);

        var max = _sec.Mfa.PhoneCodeMaxAttempts;
        var reserved = await _db.Users
            .Where(u => u.Id == userId && u.PendingPhoneCodeHash != null && u.PendingPhoneAttempts < max)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.PendingPhoneAttempts, u => u.PendingPhoneAttempts + 1), ct);
        if (reserved != 1) throw new AuthException(ResultKind.TooManyRequests, "Too many incorrect codes. Request a new code.");

        var expected = _protector.KeyedHash($"phone:{userId}", code);
        if (!TokenHasher.FixedTimeEquals(expected, user.PendingPhoneCodeHash)) throw new AuthException(ResultKind.BadRequest, invalid);

        var number = user.PendingPhoneNumber;
        var rows = await _db.Users
            .Where(u => u.Id == userId && u.PendingPhoneCodeHash == expected)
            .ExecuteUpdateAsync(s => s
                .SetProperty(u => u.PhoneNumber, (string?)number)
                .SetProperty(u => u.PhoneVerifiedAt, (DateTime?)now)
                .SetProperty(u => u.PendingPhoneNumber, (string?)null)
                .SetProperty(u => u.PendingPhoneCodeHash, (string?)null)
                .SetProperty(u => u.PendingPhoneCodeExpires, (DateTime?)null)
                .SetProperty(u => u.PendingPhoneAttempts, 0)
                .SetProperty(u => u.UpdatedAt, now), ct);
        if (rows != 1) throw new AuthException(ResultKind.BadRequest, invalid);

        await _audit.AddAndSaveAsync(AuditEvents.PhoneVerified, userId, userId, ct: ct);
        return new ServiceResponse<bool> { Data = true, Message = "Phone number verified." };
    });

    // ---- trusted devices ------------------------------------------------------------------------------------

    public Task<ServiceResponse<List<TrustedDeviceInfo>>> ListDevices(int userId, CancellationToken ct = default) => Run("ListDevices", async () =>
        new ServiceResponse<List<TrustedDeviceInfo>> { Data = await _devices.ListAsync(userId, ct), Message = "Trusted devices retrieved." });

    public Task<ServiceResponse<bool>> RevokeDevice(int userId, Guid deviceId, CancellationToken ct = default) => Run("RevokeDevice", async () =>
    {
        if (!await _devices.RevokeAsync(userId, deviceId, ct)) throw new AuthException(ResultKind.NotFound, "Device not found.");
        return new ServiceResponse<bool> { Data = true, Message = "Device revoked." };
    });

    // ---- helpers --------------------------------------------------------------------------------------------

    private bool IsMethodAllowed(MfaMethodType method) => method switch
    {
        MfaMethodType.Totp => true,
        MfaMethodType.Email => _sec.Mfa.EmailOtpEnabled,
        MfaMethodType.Sms => _sec.Mfa.SmsEnabled,
        _ => false
    };

    private bool CheckOtp(MfaChallenge challenge, MfaMethodType method, string otp, DateTime now)
    {
        if (challenge.OtpHash is null || challenge.OtpMethod != method || challenge.OtpExpiresAt <= now) return false;
        var presented = _protector.KeyedHash("mfa-otp:" + challenge.Id.ToString("N"), otp);
        return TokenHasher.FixedTimeEquals(presented, challenge.OtpHash);
    }

    private async Task<User> LoadUserAsync(int userId, CancellationToken ct) =>
        await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct) ?? throw new AuthException(ResultKind.NotFound, "User not found.");

    private async Task RequirePasswordAsync(User user, string password, CancellationToken ct)
    {
        await _abuse.EnforceAsync("reauth", _sec.RateLimits.Reauthentication, ct, $"u:{user.Id}");
        if (!_passwords.Verify(password, user).Verified) throw new AuthException(ResultKind.BadRequest, "Password is incorrect.");
    }

    /// <summary>Verifies a TOTP code and records its time step so the same code cannot be used twice.</summary>
    private async Task<bool> VerifyAndConsumeTotpAsync(User user, string code, CancellationToken ct)
    {
        if (!Identifiers.IsSixDigitCode(code) || string.IsNullOrEmpty(user.MfaSecretKey)) return false;

        string secret;
        if (_protector.IsProtected(user.MfaSecretKey))
        {
            secret = _protector.Unprotect(user.MfaSecretKey, SecretPurpose);
        }
        else
        {
            // legacy plaintext secret from before encryption-at-rest: use it, then protect it
            secret = user.MfaSecretKey;
            user.MfaSecretKey = _protector.Protect(secret, SecretPurpose);
            await _db.SaveChangesAsync(ct);
        }

        if (!new Totp(Base32Encoding.ToBytes(secret)).VerifyTotp(code, out long step, VerificationWindow.RfcSpecifiedNetworkDelay)) return false;

        var rows = await _db.Users
            .Where(u => u.Id == user.Id && (u.LastTotpStep == null || u.LastTotpStep < step))
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.LastTotpStep, (long?)step), ct);
        return rows == 1;
    }
}
