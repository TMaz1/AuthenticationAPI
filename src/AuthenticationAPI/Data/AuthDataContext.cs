using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Enums;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Data;

public class AuthDataContext(DbContextOptions<AuthDataContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshTokenRecord> RefreshTokens => Set<RefreshTokenRecord>();
    public DbSet<MfaChallenge> MfaChallenges => Set<MfaChallenge>();
    public DbSet<TrustedDevice> TrustedDevices => Set<TrustedDevice>();
    public DbSet<OutboxMessage> OutboxMessages => Set<OutboxMessage>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();

    // configuration for database schema:
    // Adds NOT NULL to DB column, default values, unique constraints and indexing in SQL
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("Users", t => t.HasCheckConstraint("CK_Users_Role", "[Role] >= 1 AND [Role] <= 5"));

            entity.HasIndex(u => u.Email).IsUnique();

            entity.Property(u => u.Email).IsRequired();
            entity.Property(u => u.PasswordHash).IsRequired();
            entity.Property(u => u.PasswordSalt).IsRequired();
            entity.Property(u => u.FirstName).IsRequired();
            entity.Property(u => u.SecurityStamp).IsRequired().HasMaxLength(64);

            // token columns hold SHA-256 hex digests; unique so one token can never match two users
            entity.Property(u => u.VerificationToken).HasMaxLength(64);
            entity.Property(u => u.PasswordResetToken).HasMaxLength(64);
            entity.HasIndex(u => u.VerificationToken).IsUnique().HasFilter("[VerificationToken] IS NOT NULL");
            entity.HasIndex(u => u.PasswordResetToken).IsUnique().HasFilter("[PasswordResetToken] IS NOT NULL");

            entity.Property(u => u.PendingPhoneNumber).HasMaxLength(16);
            entity.Property(u => u.PendingPhoneCodeHash).HasMaxLength(64);

            entity.Property(u => u.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            entity.Property(u => u.UpdatedAt).HasDefaultValueSql("GETUTCDATE()");
        });

        modelBuilder.Entity<RefreshTokenRecord>(e =>
        {
            e.ToTable("RefreshTokens");
            e.HasKey(r => r.Id);
            e.Property(r => r.TokenHash).IsRequired().HasMaxLength(64);
            e.Property(r => r.Amr).IsRequired().HasMaxLength(32);
            e.Property(r => r.RevokedReason).HasMaxLength(64);
            e.HasIndex(r => r.TokenHash).IsUnique();
            e.HasIndex(r => r.FamilyId);
            e.HasIndex(r => new { r.UserId, r.RevokedAt });
            e.HasIndex(r => r.ExpiresAt);
            e.HasOne(r => r.User).WithMany().HasForeignKey(r => r.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<MfaChallenge>(e =>
        {
            e.ToTable("MfaChallenges");
            e.HasKey(c => c.Id);
            e.Property(c => c.TokenHash).IsRequired().HasMaxLength(64);
            e.Property(c => c.OtpHash).HasMaxLength(64);
            e.HasIndex(c => c.TokenHash).IsUnique();
            e.HasIndex(c => c.ExpiresAt);
            e.HasOne(c => c.User).WithMany().HasForeignKey(c => c.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<TrustedDevice>(e =>
        {
            e.ToTable("TrustedDevices");
            e.HasKey(d => d.Id);
            e.Property(d => d.TokenHash).IsRequired().HasMaxLength(64);
            e.Property(d => d.PreviousTokenHash).HasMaxLength(64);
            e.Property(d => d.Label).HasMaxLength(64);
            e.HasIndex(d => d.TokenHash).IsUnique();
            e.HasIndex(d => d.PreviousTokenHash);
            e.HasIndex(d => new { d.UserId, d.RevokedAt });
            e.HasOne(d => d.User).WithMany().HasForeignKey(d => d.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<OutboxMessage>(e =>
        {
            e.ToTable("OutboxMessages");
            e.HasKey(m => m.Id);
            e.Property(m => m.Type).IsRequired().HasMaxLength(64);
            e.Property(m => m.IdempotencyKey).IsRequired().HasMaxLength(128);
            e.Property(m => m.LastError).HasMaxLength(256);
            e.HasIndex(m => m.IdempotencyKey).IsUnique();
            e.HasIndex(m => new { m.ProcessedAt, m.FailedAt, m.NextAttemptAt });
        });

        modelBuilder.Entity<SecurityEvent>(e =>
        {
            e.ToTable("SecurityEvents");
            e.HasKey(s => s.Id);
            e.Property(s => s.EventType).IsRequired().HasMaxLength(64);
            e.Property(s => s.Detail).HasMaxLength(256);
            e.HasIndex(s => new { s.UserId, s.OccurredAt });
            e.HasIndex(s => s.OccurredAt);
        });
    }

    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        foreach (var entry in ChangeTracker.Entries<User>())
        {
            if (entry.State == EntityState.Added)
            {
                entry.Entity.CreatedAt = now;
                entry.Entity.UpdatedAt = now;
            }
            else if (entry.State == EntityState.Modified)
            {
                entry.Entity.UpdatedAt = now;
            }
        }

        return await base.SaveChangesAsync(cancellationToken);
    }
}
