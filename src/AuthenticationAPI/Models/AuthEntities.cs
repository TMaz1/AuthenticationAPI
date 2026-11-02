using AuthenticationAPI.Models.Enums;

namespace AuthenticationAPI.Models;

/// <summary>One rotating refresh token. Only a hash of the bearer value is stored. Tokens of a login share a FamilyId.</summary>
public class RefreshTokenRecord
{
    public long Id { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }
    public Guid FamilyId { get; set; }
    public required string TokenHash { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    /// <summary>Set (atomically) when the token is exchanged. A second presentation of a consumed token signals theft/replay.</summary>
    public DateTime? ConsumedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
    /// <summary>Time the user actually authenticated (password/MFA); carried through rotation, never extended by refresh.</summary>
    public DateTime AuthTime { get; set; }
    public required string Amr { get; set; }
    public bool Persistent { get; set; }
}

/// <summary>Short-lived, single-use proof that the password step succeeded; required to complete MFA.</summary>
public class MfaChallenge
{
    public Guid Id { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }
    public required string TokenHash { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public int Attempts { get; set; }
    public DateTime? ConsumedAt { get; set; }
    public bool RememberMe { get; set; }
    public string? OtpHash { get; set; }
    public MfaMethodType? OtpMethod { get; set; }
    public DateTime? OtpExpiresAt { get; set; }
    public DateTime? OtpSentAt { get; set; }
}

/// <summary>Opaque device credential that may replace the MFA step (never the password step). Hash-only, rotated on use.</summary>
public class TrustedDevice
{
    public Guid Id { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }
    public required string TokenHash { get; set; }
    public string? PreviousTokenHash { get; set; }
    public string? Label { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
}

/// <summary>Transactional outbox row. Payload is AES-GCM protected and scrubbed once terminal.</summary>
public class OutboxMessage
{
    public Guid Id { get; set; }
    public required string Type { get; set; }
    public required string Payload { get; set; }
    public required string IdempotencyKey { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime NextAttemptAt { get; set; }
    public int Attempts { get; set; }
    public DateTime? LockedUntil { get; set; }
    public DateTime? ProcessedAt { get; set; }
    public DateTime? FailedAt { get; set; }
    public string? LastError { get; set; }
}

/// <summary>Durable security audit trail (SQL Server is the record; logs and Redis are not).</summary>
public class SecurityEvent
{
    public long Id { get; set; }
    public DateTime OccurredAt { get; set; }
    public int? UserId { get; set; }
    public int? ActorUserId { get; set; }
    public required string EventType { get; set; }
    public string? Detail { get; set; }
}
