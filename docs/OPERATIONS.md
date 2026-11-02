# Operations

## Configuration reference

All secrets come from environment variables, user-secrets or a secret store. Environment variables use `__` for `:`
(e.g. `Security__EncryptionKey`).

| Key | Default | Notes |
|---|---|---|
| `ConnectionStrings:DefaultConnection` | – (required) | SQL Server |
| `ConnectionStrings:Redis` | – | optional for startup; without it throttling is per instance |
| `AppSettings:Key` | – (required) | ≥ 32 bytes. `openssl rand -base64 48` |
| `AppSettings:PreviousKeys` | `[]` | keys still accepted for validation during rotation |
| `AppSettings:Issuer` / `Audience` | – (required) | |
| `AppSettings:AccessTokenExpiration` | 15 min (1–60) | |
| `AppSettings:RefreshTokenExpiration` | 7 days (1–90) | |
| `AppSettings:RememberMeRefreshTokenExpiration` | 30 days (≥ refresh, ≤ 180) | |
| `AppSettings:PasswordResetTokenExpiration` | 30 min | |
| `AppSettings:VerificationTokenExpiration` | 24 h | |
| `AppSettings:ClockSkewSeconds` | 30 (0–300) | tolerated issuer/validator clock difference |
| `AppSettings:AppLink` / `AppName` | – | links in emails; must be `https://` in Production |
| `Security:EncryptionKey` | – (required) | base64 32 bytes. `openssl rand -base64 32`. **Losing or changing it makes stored TOTP secrets and queued outbox payloads unreadable.** |
| `Security:Password:*` | MinLength 10, MaxLength 128, Pbkdf2Iterations 210000, composition flags false, BlockCommonPasswords true | |
| `Security:Lockout:*` | WindowMinutes 15, AccountIpMaxFailures 5, AccountMaxFailures 50, IpMaxFailures 100 | |
| `Security:RateLimits:<Name>:{Limit,WindowSeconds}` | Register 10/h, PasswordResetPerIp 10/h, PasswordResetPerAccount 5/h, ResendVerification 3/10min, TokenRedemption 30/10min, MfaVerifyPerIp 60/10min, MfaSend 5/10min, Refresh 120/min, Reauthentication 10/15min | per IP unless named otherwise |
| `Security:Mfa:*` | ChallengeMinutes 5, ChallengeMaxAttempts 5, OtpMinutes 5, OtpResendCooldownSeconds 30, PendingSetupMinutes 10, PhoneCodeMinutes 10, PhoneCodeMaxAttempts 5, EmailOtpEnabled true, SmsEnabled false, RequireMfaForAdministrators false | |
| `Security:TrustedDevices:*` | Enabled false, Days 30, MaxPerUser 10 | |
| `Security:Outbox:*` | PollSeconds 5, BatchSize 20, MaxAttempts 8, BaseDelaySeconds 10, MaxDelayMinutes 60, LeaseSeconds 120, RetentionDays 7, WorkersEnabled true | |
| `Security:Sms:Provider` | `None` | `Log` (dev), `None`, or any other name = you register your own `ISmsSender` |
| `Security:Cors:AllowedOrigins` | `[]` (CORS off) | explicit origins only |
| `Security:ForwardedHeaders:{Enabled,KnownProxies}` | off | **required behind a reverse proxy** or all clients share the proxy IP and throttle together |
| `Security:SessionCacheSeconds` | 15 | 0 = check SQL on every request |
| `Security:AdminRecentAuthMinutes` | 15 | |
| `Security:MaxSessionDays` | 90 | absolute refresh-session cap |
| `Security:AuditRetentionDays` | 365 (≥ 30) | |
| `SmtpSettings:*` | – | required in Production; otherwise a logging sender is used (nothing is delivered!) |

Invalid values fail startup with the list of problems. Set `AllowedHosts` to your host names in production.

## Database migrations and deployment

Migrations are **never applied at startup.** Order of operations for an existing deployment:

1. Back up the database.
2. Review: `dotnet ef migrations script 20250526104134_Initial 20261029120000_AddAuthHardening --idempotent -p src/AuthenticationAPI > upgrade.sql`
3. Pre-check: `SELECT COUNT(*) FROM Users WHERE Role NOT BETWEEN 1 AND 5;` must be 0 (new check constraint).
4. Run during a short maintenance window (or deploy new instances after the script; old instances are not compatible with the new schema semantics).
5. Deploy the new version with `Security:EncryptionKey` and the other required settings.
6. Verify `/health/ready`, then a login.

What the migration does to existing data (intentionally):
- sets `RefreshToken*`, `VerificationToken*`, `PasswordResetToken*` to NULL (plaintext one-time secrets must not survive). **All users are signed out; pending verification/reset links stop working.**
- gives every user a random `SecurityStamp`; existing password hashes stay valid (`PasswordHashVersion=1`) and upgrade at next login.
- existing plaintext TOTP secrets remain readable and are encrypted at next successful TOTP use.
- adds tables `RefreshTokens`, `MfaChallenges`, `TrustedDevices`, `OutboxMessages`, `SecurityEvents`.
- Rollback: `Down` drops the new objects but cannot restore the nulled secrets. Restore from backup if needed.

The migration and its snapshot were **written by hand** (no EF tooling available). Before releasing run
`dotnet ef migrations has-pending-model-changes -p src/AuthenticationAPI`; if it reports drift, regenerate the snapshot.

Assumption: the database collation is case-insensitive (SQL Server default). Lookups compare normalised lower-case emails with `=`.

## Background workers

`OutboxProcessor` (polls every `PollSeconds`) and `MaintenanceWorker` (hourly) run in every API instance.
- Several instances are safe: rows are claimed by a conditional `UPDATE … LockedUntil`; lease `LeaseSeconds`; deletions are idempotent.
- Delivery is at-least-once. Dead-lettered rows (`FailedAt` set, payload scrubbed, `LastError` = exception type) are kept 30 days: `SELECT * FROM OutboxMessages WHERE FailedAt IS NOT NULL`.
- Graceful shutdown: cancellation stops claiming; an in-flight message's lease simply expires and it is retried.
- To run workers in a dedicated process set `Security:Outbox:WorkersEnabled=false` on API instances and `true` on the worker instance (same binary).
- Set `WorkersEnabled=false` also disables cleanup on that instance.

### Adding a provider

- Email: replace `IEmailSender` (SMTP and a logging sender ship). SMS: implement `ISmsSender` and register it with `Security:Sms:Provider` set to your own name. Keep credentials in the secret store.
- Webhooks are not implemented. To add: new `NotificationTypes` constant, enqueue in the same transaction, deliver in `OutboxProcessor` with an `HttpClient` that enforces https-only, resolves DNS first and rejects private/loopback/link-local/metadata addresses (SSRF), signs `timestamp.body` with HMAC-SHA256 per destination secret, and never includes tokens/codes.

## Logging and observability

- Serilog (console + rolling file, see `serilog.json`); every request/log carries `CorrelationId` (header `X-Correlation-ID`).
- No passwords, tokens, codes, cookies or authorization headers are logged. Emails appear as `e:<12-hex>`; phone numbers masked; refresh tokens never.
- Security events are persisted in `SecurityEvents` (login lockouts are logged and metered, not row-per-request, to avoid attacker-driven table growth).
- Metrics (`System.Diagnostics.Metrics`, meter `AuthenticationAPI`): `auth.login.outcome`, `auth.refresh.outcome`, `auth.redis.fallback`, `auth.outbox.sent|retried|dead_lettered`. Tag values come from fixed sets. Inspect with `dotnet-counters monitor --counters AuthenticationAPI`, or add an OpenTelemetry exporter.
- Alert on: `auth.outbox.dead_lettered` > 0, `auth.redis.fallback` rising, `refresh.reuse_detected` / `device.replay_detected` events, `/health/ready` ≠ Healthy.
- Health: `/health/live` (process), `/health/ready` (SQL = Unhealthy on failure, Redis = Degraded). Only the status word is returned.

## Hardening checklist for production

HTTPS termination with HSTS; `ForwardedHeaders` configured; `AllowedHosts` set; secrets in a vault; Redis with TLS+auth on a
private network; SQL login with least privilege (DDL only for the migration identity); log retention configured on the sink;
`dotnet list package --vulnerable --include-transitive` in CI (provided); rotate JWT keys via `PreviousKeys`
(add new key as `Key`, move the old to `PreviousKeys`, remove it after `AccessTokenExpiration` + skew).
