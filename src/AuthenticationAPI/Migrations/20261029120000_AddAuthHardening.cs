using System;
using AuthenticationAPI.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationAPI.Migrations
{
    /// <summary>
    /// Authentication hardening: hashed one-time tokens, refresh-token families, MFA challenges, trusted devices,
    /// transactional outbox and security audit trail. Hand-authored (no EF tooling was available when written):
    /// verify with `dotnet ef migrations has-pending-model-changes` and review `dotnet ef migrations script`.
    /// </summary>
    [DbContext(typeof(AuthDataContext))]
    [Migration("20261029120000_AddAuthHardening")]
    public partial class AddAuthHardening : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Destructive-but-intended data hygiene (see docs/OPERATIONS.md): plaintext one-time secrets must not survive.
            // Outstanding refresh tokens, verification links and reset links become invalid; users sign in / request again.
            migrationBuilder.Sql(@"UPDATE [Users] SET
                [RefreshToken] = NULL, [RefreshTokenCreated] = NULL, [RefreshTokenExpires] = NULL,
                [VerificationToken] = NULL, [VerificationTokenExpires] = NULL,
                [PasswordResetToken] = NULL, [PasswordResetTokenExpires] = NULL;");

            migrationBuilder.AddColumn<bool>(
                name: "IsDisabled",
                table: "Users",
                type: "bit", nullable: false, defaultValue: false);
            migrationBuilder.AddColumn<long>(
                name: "LastTotpStep",
                table: "Users",
                type: "bigint", nullable: true);
            migrationBuilder.AddColumn<DateTime>(
                name: "PasswordChangedAt",
                table: "Users",
                type: "datetime2", nullable: true);
            migrationBuilder.AddColumn<int>(
                name: "PasswordHashIterations",
                table: "Users",
                type: "int", nullable: true);
            migrationBuilder.AddColumn<int>(
                name: "PasswordHashVersion",
                table: "Users",
                type: "int", nullable: false, defaultValue: 1);
            migrationBuilder.AddColumn<string>(
                name: "PendingMfaSecret",
                table: "Users",
                type: "nvarchar(max)", nullable: true);
            migrationBuilder.AddColumn<DateTime>(
                name: "PendingMfaSecretExpires",
                table: "Users",
                type: "datetime2", nullable: true);
            migrationBuilder.AddColumn<int>(
                name: "PendingPhoneAttempts",
                table: "Users",
                type: "int", nullable: false, defaultValue: 0);
            migrationBuilder.AddColumn<DateTime>(
                name: "PendingPhoneCodeExpires",
                table: "Users",
                type: "datetime2", nullable: true);
            migrationBuilder.AddColumn<string>(
                name: "PendingPhoneCodeHash",
                table: "Users",
                type: "nvarchar(64)", maxLength: 64, nullable: true);
            migrationBuilder.AddColumn<string>(
                name: "PendingPhoneNumber",
                table: "Users",
                type: "nvarchar(16)", maxLength: 16, nullable: true);
            migrationBuilder.AddColumn<DateTime>(
                name: "PhoneVerifiedAt",
                table: "Users",
                type: "datetime2", nullable: true);
            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "Users",
                type: "nvarchar(64)", maxLength: 64, nullable: false, defaultValue: "");

            migrationBuilder.Sql(@"UPDATE [Users] SET [SecurityStamp] = LOWER(REPLACE(CONVERT(nvarchar(36), NEWID()), '-', ''));");

            migrationBuilder.AlterColumn<string>(
                name: "PasswordResetToken",
                table: "Users",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_PasswordResetToken",
                table: "Users",
                column: "PasswordResetToken",
                unique: true,
                filter: "[PasswordResetToken] IS NOT NULL");

            migrationBuilder.AlterColumn<string>(
                name: "VerificationToken",
                table: "Users",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_VerificationToken",
                table: "Users",
                column: "VerificationToken",
                unique: true,
                filter: "[VerificationToken] IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Users_Role",
                table: "Users",
                sql: "[Role] >= 1 AND [Role] <= 5");

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Amr = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    AuthTime = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    FamilyId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Persistent = table.Column<bool>(type: "bit", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RevokedReason = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    UserId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_ExpiresAt",
                table: "RefreshTokens",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_FamilyId",
                table: "RefreshTokens",
                column: "FamilyId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_TokenHash",
                table: "RefreshTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_UserId_RevokedAt",
                table: "RefreshTokens",
                columns: new[] { "UserId", "RevokedAt" });

            migrationBuilder.CreateTable(
                name: "MfaChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Attempts = table.Column<int>(type: "int", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    OtpExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    OtpHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    OtpMethod = table.Column<int>(type: "int", nullable: true),
                    OtpSentAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RememberMe = table.Column<bool>(type: "bit", nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    UserId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaChallenges_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_ExpiresAt",
                table: "MfaChallenges",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_TokenHash",
                table: "MfaChallenges",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_UserId",
                table: "MfaChallenges",
                column: "UserId");

            migrationBuilder.CreateTable(
                name: "TrustedDevices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Label = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    LastUsedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PreviousTokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    RevokedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    UserId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrustedDevices", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TrustedDevices_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TrustedDevices_PreviousTokenHash",
                table: "TrustedDevices",
                column: "PreviousTokenHash");

            migrationBuilder.CreateIndex(
                name: "IX_TrustedDevices_TokenHash",
                table: "TrustedDevices",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TrustedDevices_UserId_RevokedAt",
                table: "TrustedDevices",
                columns: new[] { "UserId", "RevokedAt" });

            migrationBuilder.CreateTable(
                name: "OutboxMessages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Attempts = table.Column<int>(type: "int", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    FailedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    IdempotencyKey = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    LastError = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    LockedUntil = table.Column<DateTime>(type: "datetime2", nullable: true),
                    NextAttemptAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Payload = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ProcessedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Type = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OutboxMessages", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_OutboxMessages_IdempotencyKey",
                table: "OutboxMessages",
                column: "IdempotencyKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OutboxMessages_ProcessedAt_FailedAt_NextAttemptAt",
                table: "OutboxMessages",
                columns: new[] { "ProcessedAt", "FailedAt", "NextAttemptAt" });

            migrationBuilder.CreateTable(
                name: "SecurityEvents",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ActorUserId = table.Column<int>(type: "int", nullable: true),
                    Detail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    EventType = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    OccurredAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UserId = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityEvents", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_OccurredAt",
                table: "SecurityEvents",
                column: "OccurredAt");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_UserId_OccurredAt",
                table: "SecurityEvents",
                columns: new[] { "UserId", "OccurredAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "MfaChallenges");

            migrationBuilder.DropTable(
                name: "TrustedDevices");

            migrationBuilder.DropTable(
                name: "OutboxMessages");

            migrationBuilder.DropTable(
                name: "SecurityEvents");

            migrationBuilder.DropCheckConstraint(
                name: "CK_Users_Role",
                table: "Users");

            migrationBuilder.DropIndex(name: "IX_Users_PasswordResetToken", table: "Users");
            migrationBuilder.DropIndex(name: "IX_Users_VerificationToken", table: "Users");

            migrationBuilder.AlterColumn<string>(
                name: "PasswordResetToken",
                table: "Users",
                type: "nvarchar(max)",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(64)",
                oldMaxLength: 64,
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "VerificationToken",
                table: "Users",
                type: "nvarchar(max)",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(64)",
                oldMaxLength: 64,
                oldNullable: true);

            migrationBuilder.DropColumn(
                name: "IsDisabled",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "LastTotpStep",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PasswordChangedAt",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PasswordHashIterations",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PasswordHashVersion",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PendingMfaSecret",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PendingMfaSecretExpires",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PendingPhoneAttempts",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PendingPhoneCodeExpires",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PendingPhoneCodeHash",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PendingPhoneNumber",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "PhoneVerifiedAt",
                table: "Users");
            migrationBuilder.DropColumn(
                name: "SecurityStamp",
                table: "Users");
        }
    }
}
