using AuthenticationAPI.Models.Enums;

namespace AuthenticationAPI.Models;

public partial class User
{
    public int Id { get; set; }
    public required string Email { get; set; }
    public string? Username { get; set; }
    public required byte[] PasswordHash { get; set; }
    public required byte[] PasswordSalt { get; set; }
    /// <summary>1 = legacy HMAC-SHA512 (key = salt). 2 = PBKDF2-HMAC-SHA512. Legacy hashes are upgraded transparently at next successful login.</summary>
    public int PasswordHashVersion { get; set; } = 2;
    public int? PasswordHashIterations { get; set; }
    public DateTime? PasswordChangedAt { get; set; }
    public RoleType Role { get; set; } = RoleType.Viewer;
    public required string FirstName { get; set; }
    public string? LastName { get; set; }
    public string? PhoneNumber { get; set; }
    public DateTime? PhoneVerifiedAt { get; set; }

    // Legacy single-slot plaintext refresh token columns. No longer read or written (see RefreshTokenRecord); the
    // AddAuthHardening migration nulls them out. Retained so the migration is non-destructive.
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenCreated { get; set; }
    public DateTime? RefreshTokenExpires { get; set; }

    /// <summary>SHA-256 hex of the outstanding password-reset token (never the raw token).</summary>
    public string? PasswordResetToken { get; set; }
    public DateTime? PasswordResetTokenExpires { get; set; }

    /// <summary>SHA-256 hex of the outstanding verification token (never the raw token).</summary>
    public string? VerificationToken { get; set; }
    public DateTime? VerifiedAt { get; set; }
    public DateTime? VerificationTokenExpires { get; set; }

    public bool IsActive { get; set; } = false;
    public bool IsDisabled { get; set; } = false;
    /// <summary>Rotated on any change that must invalidate outstanding access tokens (password, MFA, role, disable).</summary>
    public string SecurityStamp { get; set; } = NewStamp();

    public bool TwoFactorEnabled { get; set; } = false;
    public DateTime? LastTwoFactorAt { get; set; }
    /// <summary>AES-GCM protected TOTP secret ("v1:..."). Legacy rows may still hold a plaintext base32 value until next use.</summary>
    public string? MfaSecretKey { get; set; }
    /// <summary>Highest TOTP time step already accepted; prevents replay of a code within its validity window.</summary>
    public long? LastTotpStep { get; set; }
    public string? PendingMfaSecret { get; set; }
    public DateTime? PendingMfaSecretExpires { get; set; }

    public string? PendingPhoneNumber { get; set; }
    public string? PendingPhoneCodeHash { get; set; }
    public DateTime? PendingPhoneCodeExpires { get; set; }
    public int PendingPhoneAttempts { get; set; }

    public DateTime? LastLoginAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public static string NewStamp() => Guid.NewGuid().ToString("N");
}
