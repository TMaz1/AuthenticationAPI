namespace AuthenticationAPI.Configuration;

/// <summary>Root of the strongly typed "Security" configuration section.</summary>
public sealed class SecurityOptions
{
    public const string SectionName = "Security";

    /// <summary>Base64-encoded 32-byte key used for AES-GCM encryption of MFA secrets/outbox payloads and keyed hashing of OTP codes.</summary>
    public string EncryptionKey { get; set; } = string.Empty;

    public PasswordPolicyOptions Password { get; set; } = new();
    public LockoutOptions Lockout { get; set; } = new();
    public RateLimitOptions RateLimits { get; set; } = new();
    public MfaOptions Mfa { get; set; } = new();
    public TrustedDeviceOptions TrustedDevices { get; set; } = new();
    public OutboxOptions Outbox { get; set; } = new();
    public CorsOptions Cors { get; set; } = new();
    public RedisOptions Redis { get; set; } = new();
    public ForwardedHeadersSettings ForwardedHeaders { get; set; } = new();
    public SmsOptions Sms { get; set; } = new();

    /// <summary>Seconds a per-instance cache may hold a user's session state (security stamp, disabled flag). 0 = always query SQL.</summary>
    public int SessionCacheSeconds { get; set; } = 15;

    /// <summary>Administrative mutations require authentication (password/MFA) within this many minutes.</summary>
    public int AdminRecentAuthMinutes { get; set; } = 15;

    /// <summary>Absolute lifetime cap (days) of a refresh-token family regardless of rotation.</summary>
    public int MaxSessionDays { get; set; } = 90;

    /// <summary>Retention (days) of rows in SecurityEvents before the maintenance worker deletes them.</summary>
    public int AuditRetentionDays { get; set; } = 365;
}

public sealed class PasswordPolicyOptions
{
    public int MinLength { get; set; } = 10;
    public int MaxLength { get; set; } = 128;
    public bool RequireUppercase { get; set; }
    public bool RequireLowercase { get; set; }
    public bool RequireDigit { get; set; }
    public bool RequireSpecial { get; set; }
    public bool BlockCommonPasswords { get; set; } = true;
    /// <summary>PBKDF2-HMAC-SHA512 iterations for newly created hashes.</summary>
    public int Pbkdf2Iterations { get; set; } = 210_000;
}

public sealed class LockoutOptions
{
    /// <summary>Counting window and lockout duration in minutes (fixed window).</summary>
    public int WindowMinutes { get; set; } = 15;
    /// <summary>Failures allowed for one (account, client IP) pair before that pair is locked.</summary>
    public int AccountIpMaxFailures { get; set; } = 5;
    /// <summary>Failures allowed against one account from all IPs combined. High on purpose: a low value lets anyone lock a victim out.</summary>
    public int AccountMaxFailures { get; set; } = 50;
    /// <summary>Failures allowed from one IP across all accounts (credential stuffing).</summary>
    public int IpMaxFailures { get; set; } = 100;
}

public sealed class RateLimitRule
{
    public RateLimitRule() { }
    public RateLimitRule(int limit, int windowSeconds) { Limit = limit; WindowSeconds = windowSeconds; }
    public int Limit { get; set; }
    public int WindowSeconds { get; set; }
}

public sealed class RateLimitOptions
{
    public RateLimitRule Register { get; set; } = new(10, 3600);
    public RateLimitRule PasswordResetPerIp { get; set; } = new(10, 3600);
    public RateLimitRule PasswordResetPerAccount { get; set; } = new(5, 3600);
    public RateLimitRule ResendVerification { get; set; } = new(3, 600);
    public RateLimitRule TokenRedemption { get; set; } = new(30, 600);
    public RateLimitRule MfaVerifyPerIp { get; set; } = new(60, 600);
    public RateLimitRule MfaSend { get; set; } = new(5, 600);
    public RateLimitRule Refresh { get; set; } = new(120, 60);
    public RateLimitRule Reauthentication { get; set; } = new(10, 900);
}

public sealed class MfaOptions
{
    public int ChallengeMinutes { get; set; } = 5;
    public int ChallengeMaxAttempts { get; set; } = 5;
    public int OtpMinutes { get; set; } = 5;
    public int OtpResendCooldownSeconds { get; set; } = 30;
    public int PendingSetupMinutes { get; set; } = 10;
    public int PhoneCodeMinutes { get; set; } = 10;
    public int PhoneCodeMaxAttempts { get; set; } = 5;
    /// <summary>Existing behaviour: email OTP is an allowed fallback method. Disable to make TOTP the only second factor.</summary>
    public bool EmailOtpEnabled { get; set; } = true;
    /// <summary>SMS OTP. Disabled by default; requires a configured ISmsSender.</summary>
    public bool SmsEnabled { get; set; }
    /// <summary>When true, accounts with the Administrator role cannot disable their own MFA.</summary>
    public bool RequireMfaForAdministrators { get; set; }
}

public sealed class TrustedDeviceOptions
{
    public bool Enabled { get; set; }
    public int Days { get; set; } = 30;
    public int MaxPerUser { get; set; } = 10;
}

public sealed class OutboxOptions
{
    public int PollSeconds { get; set; } = 5;
    public int BatchSize { get; set; } = 20;
    public int MaxAttempts { get; set; } = 8;
    public int BaseDelaySeconds { get; set; } = 10;
    public int MaxDelayMinutes { get; set; } = 60;
    public int LeaseSeconds { get; set; } = 120;
    public int RetentionDays { get; set; } = 7;
    public bool WorkersEnabled { get; set; } = true;
}

public sealed class CorsOptions
{
    /// <summary>Explicit origins. Empty = CORS disabled. "*" is rejected.</summary>
    public string[] AllowedOrigins { get; set; } = [];
}

public sealed class RedisOptions
{
    public string KeyPrefix { get; set; } = "authapi:";
    public int ConnectTimeoutMs { get; set; } = 2000;
    public int OperationTimeoutMs { get; set; } = 1000;
}

public sealed class ForwardedHeadersSettings
{
    public bool Enabled { get; set; }
    public string[] KnownProxies { get; set; } = [];
}

public sealed class SmsOptions
{
    /// <summary>"None" (default) or "Log" (development only; logs a masked destination, never the code).</summary>
    public string Provider { get; set; } = "None";
}
