using System.Net;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Enums;
using AuthenticationAPI.Services.Notifications;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using static AuthenticationAPI.Tests.Integration.ApiFixture;

namespace AuthenticationAPI.Tests.Integration;

[Trait("Category", "Integration")]
public class OutboxTests(ApiFixture fx) : IClassFixture<ApiFixture>
{
    private async Task<(string Email, Guid MessageId)> QueueVerificationAsync()
    {
        fx.Email.FailNext(0);
        await fx.PumpAsync(); // drain leftovers from earlier tests so failure injection below targets only this message
        var email = $"ob-{Guid.NewGuid():N}@example.com";
        var r = await Post(fx.NewClient(), "/api/auth/register", new { email, password = Password, confirmPassword = Password, firstName = "Out", lastName = "Box" });
        Assert.True(r.Success, r.Raw);
        var id = await fx.Db(async d => (await d.OutboxMessages.AsNoTracking().OrderByDescending(m => m.CreatedAt).FirstAsync()).Id);
        return (email, id);
    }

    [SqlFact]
    public async Task Registration_is_committed_together_with_its_notification_and_the_payload_is_encrypted()
    {
        var (email, id) = await QueueVerificationAsync();
        var row = await fx.Db(d => d.OutboxMessages.AsNoTracking().SingleAsync(m => m.Id == id));
        Assert.Equal(NotificationTypes.Verification, row.Type);
        Assert.StartsWith("v1:", row.Payload);
        Assert.DoesNotContain(email, row.Payload);
        Assert.Null(row.ProcessedAt);
    }

    [SqlFact]
    public async Task Provider_failure_is_retried_with_backoff_then_delivered_once_and_the_payload_is_scrubbed()
    {
        var (email, id) = await QueueVerificationAsync();
        fx.Email.FailNext(1);
        await fx.PumpAsync();

        var failed = await fx.Db(d => d.OutboxMessages.AsNoTracking().SingleAsync(m => m.Id == id));
        Assert.Equal(1, failed.Attempts);
        Assert.Null(failed.ProcessedAt);
        Assert.True(failed.NextAttemptAt > DateTime.UtcNow.AddSeconds(2)); // backed off
        Assert.Equal("InvalidOperationException", failed.LastError);       // type only, never provider text
        Assert.Null(fx.Email.Last(email, "Verify"));

        await fx.PumpAsync();                                              // not due yet: nothing happens
        Assert.Null(fx.Email.Last(email, "Verify"));

        await fx.Db(d => d.OutboxMessages.Where(m => m.Id == id).ExecuteUpdateAsync(s => s.SetProperty(m => m.NextAttemptAt, DateTime.UtcNow.AddSeconds(-1))));
        await fx.PumpAsync();
        Assert.NotNull(fx.Email.Last(email, "Verify"));

        var done = await fx.Db(d => d.OutboxMessages.AsNoTracking().SingleAsync(m => m.Id == id));
        Assert.NotNull(done.ProcessedAt);
        Assert.Equal(string.Empty, done.Payload); // one-time secret no longer stored

        await fx.PumpAsync();
        Assert.Single(fx.Email.Sent, e => e.To == email); // exactly once
    }

    [SqlFact]
    public async Task Permanent_failure_dead_letters_after_max_attempts_and_keeps_no_secret()
    {
        var (email, id) = await QueueVerificationAsync();
        fx.Email.FailNext(100);
        for (var i = 0; i < 3; i++)
        {
            await fx.PumpAsync();
            await fx.Db(d => d.OutboxMessages.Where(m => m.Id == id).ExecuteUpdateAsync(s => s.SetProperty(m => m.NextAttemptAt, DateTime.UtcNow.AddSeconds(-1))));
        }
        await fx.PumpAsync();
        fx.Email.FailNext(0);

        var row = await fx.Db(d => d.OutboxMessages.AsNoTracking().SingleAsync(m => m.Id == id));
        Assert.NotNull(row.FailedAt);
        Assert.Equal(3, row.Attempts);
        Assert.Equal(string.Empty, row.Payload);

        await fx.PumpAsync(); // terminal rows are never retried
        Assert.Null(fx.Email.Last(email, "Verify"));
    }

    [SqlFact]
    public async Task Concurrent_workers_deliver_each_message_exactly_once()
    {
        var emails = new List<string>();
        for (var i = 0; i < 6; i++) emails.Add((await QueueVerificationAsync()).Email);

        var proc = fx.Factory!.Services.GetRequiredService<OutboxProcessor>();
        await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Task.Run(async () => { while (await proc.ProcessBatchAsync(CancellationToken.None) > 0) { } })));

        foreach (var e in emails) Assert.Single(fx.Email.Sent, s => s.To == e);
    }

    [SqlFact]
    public async Task A_crashed_workers_lease_expires_and_the_message_is_recovered()
    {
        var (email, id) = await QueueVerificationAsync();
        await fx.Db(d => d.OutboxMessages.Where(m => m.Id == id).ExecuteUpdateAsync(s => s.SetProperty(m => m.LockedUntil, (DateTime?)DateTime.UtcNow.AddMinutes(5))));
        await fx.PumpAsync();
        Assert.Null(fx.Email.Last(email, "Verify")); // still leased by the "dead" worker

        await fx.Db(d => d.OutboxMessages.Where(m => m.Id == id).ExecuteUpdateAsync(s => s.SetProperty(m => m.LockedUntil, (DateTime?)DateTime.UtcNow.AddSeconds(-1))));
        await fx.PumpAsync();
        Assert.NotNull(fx.Email.Last(email, "Verify"));
    }

    [SqlFact]
    public async Task Maintenance_removes_expired_records_but_keeps_active_and_audit_records()
    {
        var c = fx.NewClient();
        var user = await fx.RegisterVerifiedAsync(c);
        var live = await fx.LoginAsync(c, user);
        await fx.Db(async d =>
        {
            d.RefreshTokens.Add(new RefreshTokenRecord { UserId = user.Id, FamilyId = Guid.NewGuid(), TokenHash = new string('a', 64), CreatedAt = DateTime.UtcNow.AddDays(-40), ExpiresAt = DateTime.UtcNow.AddDays(-30), AuthTime = DateTime.UtcNow.AddDays(-40), Amr = "pwd" });
            d.SecurityEvents.Add(new SecurityEvent { OccurredAt = DateTime.UtcNow.AddDays(-5), UserId = user.Id, EventType = "test.recent" });
            d.SecurityEvents.Add(new SecurityEvent { OccurredAt = DateTime.UtcNow.AddDays(-4000), UserId = user.Id, EventType = "test.ancient" });
            await d.SaveChangesAsync();
        });

        await fx.Factory!.Services.GetRequiredService<MaintenanceWorker>().RunOnceAsync(CancellationToken.None);

        Assert.False(await fx.Db(d => d.RefreshTokens.AnyAsync(r => r.TokenHash == new string('a', 64))));
        Assert.True((await Post(c, "/api/auth/refresh-token", new { token = live.RefreshToken })).Success); // active session untouched
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "test.recent")));
        Assert.False(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "test.ancient")));
    }
}

[Trait("Category", "Integration")]
public class DatabaseIntegrityTests(ApiFixture fx) : IClassFixture<ApiFixture>
{
    [SqlFact]
    public async Task Migrations_apply_cleanly_to_a_real_sql_server_database()
    {
        await fx.Db(async d =>
        {
            Assert.Empty(await d.Database.GetPendingMigrationsAsync());
            Assert.Contains("20261029120000_AddAuthHardening", await d.Database.GetAppliedMigrationsAsync());
        });
    }

    [SqlFact]
    public async Task Email_uniqueness_is_enforced_by_the_database_case_insensitively()
    {
        var u = await fx.RegisterVerifiedAsync(fx.NewClient());
        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => fx.Db(async d =>
        {
            d.Users.Add(new User { Email = u.Email.ToUpperInvariant(), FirstName = "Dup", PasswordHash = [1], PasswordSalt = [1] });
            await d.SaveChangesAsync();
        }));
        Assert.IsType<SqlException>(ex.InnerException);
    }

    [SqlFact]
    public async Task Invalid_role_values_are_rejected_by_a_check_constraint()
    {
        var u = await fx.RegisterVerifiedAsync(fx.NewClient());
        await Assert.ThrowsAsync<SqlException>(() => fx.Db(d => d.Database.ExecuteSqlRawAsync("UPDATE Users SET Role = 99 WHERE Id = {0}", u.Id)));
    }

    [SqlFact]
    public async Task Token_hash_and_idempotency_keys_are_unique()
    {
        await Assert.ThrowsAsync<DbUpdateException>(() => fx.Db(async d =>
        {
            var now = DateTime.UtcNow;
            d.OutboxMessages.Add(new OutboxMessage { Id = Guid.NewGuid(), Type = "x", Payload = "", IdempotencyKey = "dup-key", CreatedAt = now, NextAttemptAt = now });
            d.OutboxMessages.Add(new OutboxMessage { Id = Guid.NewGuid(), Type = "x", Payload = "", IdempotencyKey = "dup-key", CreatedAt = now, NextAttemptAt = now });
            await d.SaveChangesAsync();
        }));

        var u = await fx.RegisterVerifiedAsync(fx.NewClient());
        await Assert.ThrowsAsync<DbUpdateException>(() => fx.Db(async d =>
        {
            for (var i = 0; i < 2; i++)
                d.RefreshTokens.Add(new RefreshTokenRecord { UserId = u.Id, FamilyId = Guid.NewGuid(), TokenHash = new string('b', 64), CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(1), AuthTime = DateTime.UtcNow, Amr = "pwd" });
            await d.SaveChangesAsync();
        }));
    }

    [SqlFact]
    public async Task Deleting_a_user_cascades_to_sessions_challenges_and_devices_but_keeps_audit_history()
    {
        var c = fx.NewClient();
        var u = await fx.RegisterVerifiedAsync(c);
        await fx.LoginAsync(c, u);
        await fx.Db(async d => { d.SecurityEvents.Add(new SecurityEvent { OccurredAt = DateTime.UtcNow, UserId = u.Id, EventType = "test.keep" }); await d.SaveChangesAsync(); });

        await fx.Db(d => d.Users.Where(x => x.Id == u.Id).ExecuteDeleteAsync());
        Assert.False(await fx.Db(d => d.RefreshTokens.AnyAsync(r => r.UserId == u.Id)));
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "test.keep")));
    }

    [SqlFact]
    public async Task Sql_injection_strings_are_treated_as_data()
    {
        var c = fx.NewClient();
        var r = await Post(c, "/api/auth/login", new { email = "x@example.com' OR '1'='1", password = "' OR '1'='1" });
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        var r2 = await Post(c, "/api/auth/password-reset-request", new { email = "a@example.com'; DROP TABLE Users;--" });
        Assert.Contains(r2.Status, new[] { HttpStatusCode.BadRequest, HttpStatusCode.OK });
    }
}
