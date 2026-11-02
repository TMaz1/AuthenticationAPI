using System.Text.Json;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services.Security;

namespace AuthenticationAPI.Services.Notifications;

public static class NotificationTypes
{
    public const string Verification = "email.verification";
    public const string PasswordReset = "email.password_reset";
    public const string MfaCode = "email.mfa_code";
    public const string PasswordChanged = "email.password_changed";
    public const string MfaDisabled = "email.mfa_disabled";
    public const string SmsCode = "sms.code";
}

/// <param name="To">Email address or E.164 phone number.</param>
/// <param name="Link">Absolute link (verification/reset). Contains a one-time secret; the payload is encrypted and scrubbed after delivery.</param>
/// <param name="Code">One-time code (MFA/phone). Same handling as Link.</param>
/// <param name="Expiry">Expiry in the unit the template expects (hours for verification, minutes otherwise).</param>
public sealed record NotificationPayload(string To, string? Link = null, string? Code = null, int Expiry = 0);

public interface INotificationOutbox
{
    /// <summary>
    /// Adds a message to the caller's current unit of work. It becomes durable in the SAME SQL transaction as the
    /// state change that caused it (transactional outbox); delivery happens later in OutboxProcessor.
    /// </summary>
    void Enqueue(string type, NotificationPayload payload, string? idempotencyKey = null);
}

public sealed class NotificationOutbox(AuthDataContext context, ISecretProtector protector) : INotificationOutbox
{
    public const string PayloadPurpose = "outbox-payload";

    public void Enqueue(string type, NotificationPayload payload, string? idempotencyKey = null)
    {
        var now = DateTime.UtcNow;
        context.OutboxMessages.Add(new OutboxMessage
        {
            Id = Guid.NewGuid(),
            Type = type,
            Payload = protector.Protect(JsonSerializer.Serialize(payload), PayloadPurpose),
            IdempotencyKey = idempotencyKey ?? $"{type}:{Guid.NewGuid():N}",
            CreatedAt = now,
            NextAttemptAt = now
        });
    }
}
