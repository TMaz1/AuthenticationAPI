using System.Text.Json;
using AuthenticationAPI.Configuration;
using AuthenticationAPI.Data;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Utils.Logger;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Notifications;

public static class OutboxBackoff
{
    /// <summary>Exponential backoff with "equal jitter": delay in [d/2, d], d = min(base * 2^(attempt-1), max).</summary>
    public static TimeSpan ComputeDelay(int attempt, OutboxOptions o, double jitter01)
    {
        var exp = Math.Min(Math.Max(attempt - 1, 0), 20);
        var seconds = Math.Min(o.BaseDelaySeconds * Math.Pow(2, exp), o.MaxDelayMinutes * 60.0);
        var j = Math.Clamp(jitter01, 0.0, 1.0);
        return TimeSpan.FromSeconds(seconds * (0.5 + 0.5 * j));
    }
}

/// <summary>
/// Durable delivery of notifications. Safe with several instances: a row is claimed with a conditional UPDATE
/// (lease), so only one worker owns it at a time. Delivery is at-least-once; a crash after sending but before the
/// row is marked processed re-sends after the lease expires (a duplicate email/SMS is the accepted trade-off).
/// </summary>
public sealed class OutboxProcessor(
    IServiceScopeFactory scopes,
    IOptions<SecurityOptions> options,
    IAppLogger<OutboxProcessor> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value.Outbox;
        if (!o.WorkersEnabled) return;

        while (!stoppingToken.IsCancellationRequested)
        {
            var processed = 0;
            try
            {
                processed = await ProcessBatchAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Outbox batch failed");
            }

            if (processed == 0)
            {
                try { await Task.Delay(TimeSpan.FromSeconds(o.PollSeconds), stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    /// <summary>Processes one batch; returns the number of messages handled. Public so tests can drive it deterministically.</summary>
    public async Task<int> ProcessBatchAsync(CancellationToken ct)
    {
        var o = options.Value.Outbox;
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDataContext>();
        var now = DateTime.UtcNow;

        var ids = await db.OutboxMessages.AsNoTracking()
            .Where(m => m.ProcessedAt == null && m.FailedAt == null && m.NextAttemptAt <= now && (m.LockedUntil == null || m.LockedUntil < now))
            .OrderBy(m => m.NextAttemptAt)
            .Select(m => m.Id)
            .Take(o.BatchSize)
            .ToListAsync(ct);

        var handled = 0;
        foreach (var id in ids)
        {
            ct.ThrowIfCancellationRequested();

            var claimTime = DateTime.UtcNow;
            var leaseUntil = claimTime.AddSeconds(o.LeaseSeconds);

            var claimed = await db.OutboxMessages
                .Where(m =>
                    m.Id == id &&
                    m.ProcessedAt == null &&
                    m.FailedAt == null &&
                    (m.LockedUntil == null || m.LockedUntil < claimTime))
                .ExecuteUpdateAsync(
                    s => s.SetProperty(m => m.LockedUntil, leaseUntil),
                    ct);

            if (claimed != 1)
                continue;

            var msg = await db.OutboxMessages
                .FirstAsync(m => m.Id == id, ct);

            await DeliverAsync(scope.ServiceProvider, db, msg, o, ct);
            handled++;
        }

        return handled;
    }

    private async Task DeliverAsync(IServiceProvider sp, AuthDataContext db, OutboxMessage msg, OutboxOptions o, CancellationToken ct)
    {
        try
        {
            var protector = sp.GetRequiredService<ISecretProtector>();
            var payload = JsonSerializer.Deserialize<NotificationPayload>(protector.Unprotect(msg.Payload, NotificationOutbox.PayloadPurpose))
                          ?? throw new InvalidOperationException("Empty outbox payload.");

            if (msg.Type == NotificationTypes.SmsCode)
            {
                var app = sp.GetRequiredService<IOptions<AppSettings>>().Value;
                var text = $"Your {app.AppName} verification code is {payload.Code}. It expires in {payload.Expiry} minutes. Never share this code.";
                await sp.GetRequiredService<ISmsSender>().SendAsync(payload.To, text, ct);
            }
            else
            {
                var rendered = sp.GetRequiredService<IEmailTemplateRenderer>().Render(msg.Type, payload);
                await sp.GetRequiredService<IEmailSender>().SendAsync(payload.To, rendered.Subject, rendered.Html, ct);
            }

            msg.ProcessedAt = DateTime.UtcNow;
            msg.Payload = string.Empty; // scrub the one-time secret as soon as it is no longer needed
            msg.LockedUntil = null;
            msg.LastError = null;
            await db.SaveChangesAsync(CancellationToken.None);
            AuthMetrics.OutboxSent.Add(1, new KeyValuePair<string, object?>("type", msg.Type));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // shutdown: leave the lease; the message is retried after it expires
        }
        catch (Exception ex)
        {
            msg.Attempts++;
            msg.LastError = ex.GetType().Name; // type only: messages can contain addresses or provider details
            msg.LockedUntil = null;
            if (msg.Attempts >= o.MaxAttempts)
            {
                msg.FailedAt = DateTime.UtcNow; // terminal (dead letter): kept for visibility, payload removed
                msg.Payload = string.Empty;
                AuthMetrics.OutboxDeadLettered.Add(1, new KeyValuePair<string, object?>("type", msg.Type));
                logger.Error(ex, "Outbox message {MessageId} ({Type}) dead-lettered after {Attempts} attempts", msg.Id, msg.Type, msg.Attempts);
            }
            else
            {
                msg.NextAttemptAt = DateTime.UtcNow + OutboxBackoff.ComputeDelay(msg.Attempts, o, Random.Shared.NextDouble());
                AuthMetrics.OutboxRetried.Add(1, new KeyValuePair<string, object?>("type", msg.Type));
                logger.Warn("Outbox message {MessageId} ({Type}) failed (attempt {Attempts}); will retry", msg.Id, msg.Type, msg.Attempts);
            }

            await db.SaveChangesAsync(CancellationToken.None);
        }
    }
}

/// <summary>Deletes expired security records. Idempotent; safe if several instances run it.</summary>
public sealed class MaintenanceWorker(
    IServiceScopeFactory scopes,
    IOptions<SecurityOptions> options,
    IAppLogger<MaintenanceWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Outbox.WorkersEnabled) return;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Maintenance run failed");
            }

            try { await Task.Delay(TimeSpan.FromHours(1), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var o = options.Value;
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDataContext>();
        var now = DateTime.UtcNow;
        var graceCutoff = now.AddDays(-1);
        var outboxCutoff = now.AddDays(-o.Outbox.RetentionDays);
        var failedCutoff = now.AddDays(-Math.Max(o.Outbox.RetentionDays, 30));
        var auditCutoff = now.AddDays(-o.AuditRetentionDays);

        // Only rows that can no longer authorize anything are removed; consumed/revoked refresh tokens are kept until
        // they expire so reuse detection keeps working.
        var tokens = await db.RefreshTokens.Where(r => r.ExpiresAt < graceCutoff).ExecuteDeleteAsync(ct);
        var challenges = await db.MfaChallenges.Where(c => c.ExpiresAt < graceCutoff).ExecuteDeleteAsync(ct);
        var devices = await db.TrustedDevices.Where(d => d.ExpiresAt < graceCutoff || (d.RevokedAt != null && d.RevokedAt < failedCutoff)).ExecuteDeleteAsync(ct);
        var sent = await db.OutboxMessages.Where(m => m.ProcessedAt != null && m.ProcessedAt < outboxCutoff).ExecuteDeleteAsync(ct);
        var dead = await db.OutboxMessages.Where(m => m.FailedAt != null && m.FailedAt < failedCutoff).ExecuteDeleteAsync(ct);
        var audit = await db.SecurityEvents.Where(e => e.OccurredAt < auditCutoff).ExecuteDeleteAsync(ct);

        await db.Users.Where(u => u.VerificationToken != null && u.VerificationTokenExpires < now)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.VerificationToken, (string?)null).SetProperty(u => u.VerificationTokenExpires, (DateTime?)null), ct);
        await db.Users.Where(u => u.PasswordResetToken != null && u.PasswordResetTokenExpires < now)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.PasswordResetToken, (string?)null).SetProperty(u => u.PasswordResetTokenExpires, (DateTime?)null), ct);
        await db.Users.Where(u => u.PendingMfaSecret != null && u.PendingMfaSecretExpires < now)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.PendingMfaSecret, (string?)null).SetProperty(u => u.PendingMfaSecretExpires, (DateTime?)null), ct);

        logger.Info("Maintenance removed tokens={Tokens} challenges={Challenges} devices={Devices} outboxSent={Sent} outboxDead={Dead} audit={Audit}",
            tokens, challenges, devices, sent, dead, audit);
    }
}
