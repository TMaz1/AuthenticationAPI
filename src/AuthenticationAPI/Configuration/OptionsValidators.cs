using AuthenticationAPI.Dtos;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Configuration;

public sealed class JwtSettingsValidator : IValidateOptions<JwtSettings>
{
    public ValidateOptionsResult Validate(string? name, JwtSettings o)
    {
        var errors = new List<string>();
        if (!IsStrongKey(o.Key)) errors.Add("AppSettings:Key must be configured with at least 32 bytes of secret material (not a placeholder).");
        foreach (var k in o.PreviousKeys)
            if (!IsStrongKey(k)) errors.Add("AppSettings:PreviousKeys entries must each be at least 32 bytes and not placeholders.");
        if (string.IsNullOrWhiteSpace(o.Issuer) || o.Issuer.StartsWith('<')) errors.Add("AppSettings:Issuer is required.");
        if (string.IsNullOrWhiteSpace(o.Audience) || o.Audience.StartsWith('<')) errors.Add("AppSettings:Audience is required.");
        if (o.AccessTokenExpiration is < 1 or > 60) errors.Add("AppSettings:AccessTokenExpiration must be 1-60 minutes.");
        if (o.RefreshTokenExpiration is < 1 or > 90) errors.Add("AppSettings:RefreshTokenExpiration must be 1-90 days.");
        if (o.RememberMeRefreshTokenExpiration < o.RefreshTokenExpiration || o.RememberMeRefreshTokenExpiration > 180) errors.Add("AppSettings:RememberMeRefreshTokenExpiration must be >= RefreshTokenExpiration and <= 180 days.");
        if (o.PasswordResetTokenExpiration is < 5 or > 120) errors.Add("AppSettings:PasswordResetTokenExpiration must be 5-120 minutes.");
        if (o.VerificationTokenExpiration is < 1 or > 168) errors.Add("AppSettings:VerificationTokenExpiration must be 1-168 hours.");
        if (o.ClockSkewSeconds is < 0 or > 300) errors.Add("AppSettings:ClockSkewSeconds must be 0-300.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    internal static bool IsStrongKey(string? key) =>
        !string.IsNullOrWhiteSpace(key) && !key.StartsWith('<') && System.Text.Encoding.UTF8.GetByteCount(key) >= 32;
}

public sealed class SecurityOptionsValidator : IValidateOptions<SecurityOptions>
{
    public ValidateOptionsResult Validate(string? name, SecurityOptions o)
    {
        var errors = new List<string>();

        if (!TryDecodeKey(o.EncryptionKey))
            errors.Add("Security:EncryptionKey must be a base64-encoded 32-byte key (generate with: openssl rand -base64 32).");

        var p = o.Password;
        if (p.MinLength < 8 || p.MinLength > p.MaxLength) errors.Add("Security:Password:MinLength must be >= 8 and <= MaxLength.");
        if (p.MaxLength is < 64 or > 1024) errors.Add("Security:Password:MaxLength must be 64-1024.");
        if (p.Pbkdf2Iterations < 100_000 || p.Pbkdf2Iterations > 5_000_000) errors.Add("Security:Password:Pbkdf2Iterations must be 100000-5000000.");

        var l = o.Lockout;
        if (l.WindowMinutes is < 1 or > 1440) errors.Add("Security:Lockout:WindowMinutes must be 1-1440.");
        if (l.AccountIpMaxFailures < 3) errors.Add("Security:Lockout:AccountIpMaxFailures must be >= 3.");
        if (l.AccountMaxFailures < l.AccountIpMaxFailures) errors.Add("Security:Lockout:AccountMaxFailures must be >= AccountIpMaxFailures.");
        if (l.IpMaxFailures < l.AccountIpMaxFailures) errors.Add("Security:Lockout:IpMaxFailures must be >= AccountIpMaxFailures.");

        foreach (var (ruleName, rule) in EnumerateRules(o.RateLimits))
            if (rule.Limit < 1 || rule.WindowSeconds < 1 || rule.WindowSeconds > 86_400)
                errors.Add($"Security:RateLimits:{ruleName} needs Limit >= 1 and WindowSeconds 1-86400.");

        var m = o.Mfa;
        if (m.ChallengeMinutes is < 1 or > 30) errors.Add("Security:Mfa:ChallengeMinutes must be 1-30.");
        if (m.ChallengeMaxAttempts is < 1 or > 10) errors.Add("Security:Mfa:ChallengeMaxAttempts must be 1-10.");
        if (m.OtpMinutes is < 1 or > 15) errors.Add("Security:Mfa:OtpMinutes must be 1-15.");
        if (m.OtpResendCooldownSeconds is < 0 or > 600) errors.Add("Security:Mfa:OtpResendCooldownSeconds must be 0-600.");
        if (m.PhoneCodeMinutes is < 1 or > 30) errors.Add("Security:Mfa:PhoneCodeMinutes must be 1-30.");
        if (m.PhoneCodeMaxAttempts is < 1 or > 10) errors.Add("Security:Mfa:PhoneCodeMaxAttempts must be 1-10.");
        if (m.SmsEnabled && string.Equals(o.Sms.Provider, "None", StringComparison.OrdinalIgnoreCase))
            errors.Add("Security:Mfa:SmsEnabled requires an SMS provider (Security:Sms:Provider). Register a production ISmsSender implementation; 'None' cannot deliver codes.");

        if (o.TrustedDevices.Days is < 1 or > 90) errors.Add("Security:TrustedDevices:Days must be 1-90.");
        if (o.TrustedDevices.MaxPerUser is < 1 or > 50) errors.Add("Security:TrustedDevices:MaxPerUser must be 1-50.");

        var ob = o.Outbox;
        if (ob.PollSeconds is < 1 or > 300) errors.Add("Security:Outbox:PollSeconds must be 1-300.");
        if (ob.BatchSize is < 1 or > 500) errors.Add("Security:Outbox:BatchSize must be 1-500.");
        if (ob.MaxAttempts is < 1 or > 50) errors.Add("Security:Outbox:MaxAttempts must be 1-50.");
        if (ob.BaseDelaySeconds is < 1 or > 3600) errors.Add("Security:Outbox:BaseDelaySeconds must be 1-3600.");
        if (ob.LeaseSeconds < 10) errors.Add("Security:Outbox:LeaseSeconds must be >= 10.");

        foreach (var origin in o.Cors.AllowedOrigins)
            if (origin == "*" || !Uri.TryCreate(origin, UriKind.Absolute, out var u) || (u.Scheme != "https" && u.Scheme != "http"))
                errors.Add($"Security:Cors:AllowedOrigins contains an invalid or wildcard origin ('{origin}').");

        foreach (var proxy in o.ForwardedHeaders.KnownProxies)
            if (!System.Net.IPAddress.TryParse(proxy, out _)) errors.Add($"Security:ForwardedHeaders:KnownProxies contains an invalid IP ('{proxy}').");

        if (o.SessionCacheSeconds is < 0 or > 300) errors.Add("Security:SessionCacheSeconds must be 0-300.");
        if (o.AdminRecentAuthMinutes is < 1 or > 240) errors.Add("Security:AdminRecentAuthMinutes must be 1-240.");
        if (o.MaxSessionDays is < 1 or > 365) errors.Add("Security:MaxSessionDays must be 1-365.");
        if (o.AuditRetentionDays < 30) errors.Add("Security:AuditRetentionDays must be >= 30.");

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    internal static bool TryDecodeKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        Span<byte> buffer = stackalloc byte[64];
        return Convert.TryFromBase64String(value, buffer, out var written) && written == 32;
    }

    private static IEnumerable<(string, RateLimitRule)> EnumerateRules(RateLimitOptions r)
    {
        yield return (nameof(r.Register), r.Register);
        yield return (nameof(r.PasswordResetPerIp), r.PasswordResetPerIp);
        yield return (nameof(r.PasswordResetPerAccount), r.PasswordResetPerAccount);
        yield return (nameof(r.ResendVerification), r.ResendVerification);
        yield return (nameof(r.TokenRedemption), r.TokenRedemption);
        yield return (nameof(r.MfaVerifyPerIp), r.MfaVerifyPerIp);
        yield return (nameof(r.MfaSend), r.MfaSend);
        yield return (nameof(r.Refresh), r.Refresh);
        yield return (nameof(r.Reauthentication), r.Reauthentication);
    }
}
