# Authentication API

ASP.NET Core 8 authentication service: JWT access tokens, rotating refresh tokens, email verification, password
recovery, TOTP / email / SMS multi-factor authentication, optional trusted devices, administrative controls,
SQL Server (EF Core) persistence, Redis-backed throttling and a transactional outbox for notifications.

## Layout

```
AuthenticationAPI.sln
src/AuthenticationAPI/            the API (controllers, services, EF Core model, migrations)
  Configuration/                  strongly-typed options + startup validators
  Controllers/AuthController.cs   HTTP surface (thin; no business logic)
  Services/Authentication/        registration, login, recovery, admin operations
  Services/Mfa/                   TOTP/email/SMS MFA, phone enrolment, trusted devices
  Services/Token/                 JWT issuing, refresh-token families, session helper
  Services/Security/              hashing, AES-GCM protector, rate-limit stores, throttling, audit, session validator
  Services/Notifications/         outbox, SMTP/SMS provider abstractions, templates, background workers
  Startup/                        composition root (service + pipeline extensions)
tests/AuthenticationAPI.Tests/    Unit/ (no infrastructure) and Integration/ (real SQL Server, optional Redis)
docs/                             API, security, Redis, operations, testing
.github/workflows/                CI (build, format, unit, integration) and manual mutation testing
```

## Local Development Setup

The API supports flexible development environments. SQL Server and Redis can run locally, in Docker containers, or on separate infrastructure.

Both services are independently configurable through connection strings, allowing developers to use whichever infrastructure arrangement suits their environment.

### Prerequisites

- .NET 8 SDK
- SQL Server (local, Docker or remote instance)
- Redis (local, Docker or remote instance)
- Docker Desktop (if using containerised infrastructure)
- PowerShell or a compatible terminal

### 1\. Start infrastructure

The repository includes a Docker Compose configuration for running SQL Server and Redis.

**Start both services:**

powershell

```powershell
$env:SA_PASSWORD = "<YOUR_LOCAL_SA_PASSWORD>"
docker compose up -d
```

The `SA_PASSWORD` environment variable supplies the SQL Server administrator password expected by the Docker Compose configuration.

To start individual services, use their Compose service names:

powershell

```powershell
docker compose up -d redis
```

Alternatively, use independently installed or externally hosted SQL Server and Redis instances. Ensure both services are accessible from the machine running the API.

### 2\. Configure application secrets

Navigate to the API project:

powershell

```powershell
cd src/AuthenticationAPI
```

Initialise .NET User Secrets:

powershell

```powershell
dotnet user-secrets init
```

Configure the connection strings according to your infrastructure.

**SQL Server — Docker example:**

powershell

```powershell
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Server=localhost,1433;Database=AuthApi;User Id=sa;Password=<YOUR_LOCAL_SA_PASSWORD>;TrustServerCertificate=True"
```

Use the same password configured through `SA_PASSWORD`.

**SQL Server — Local SQL Server Express example:**

powershell

```powershell
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Server=localhost\SQLEXPRESS;Database=AuthApi;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=True"
```

Adjust the server address, authentication method and connection options to match your SQL Server installation.

**Redis:**

powershell

```powershell
dotnet user-secrets set "ConnectionStrings:Redis" "localhost:6379"
```

For remote or secured Redis instances, provide the appropriate connection details and authentication configuration supported by the application.

**Application and encryption keys:**

Generate cryptographically secure keys:

powershell

```powershell
$appKey = [Convert]::ToBase64String(
    [Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
)

$encryptionKey = [Convert]::ToBase64String(
    [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
)

dotnet user-secrets set "AppSettings:Key" $appKey
dotnet user-secrets set "Security:EncryptionKey" $encryptionKey
```

**Development SMS provider:**

powershell

```powershell
dotnet user-secrets set "Security:Sms:Provider" "Log"
```

The `Log` provider is intended for development only and does not send real SMS messages.

Verify the configured secrets:

powershell

```powershell
dotnet user-secrets list
```

### 3\. Build and initialise the database

Build the application:

powershell

```powershell
dotnet build
```

Apply Entity Framework Core migrations:

powershell

```powershell
dotnet ef database update
```

Database schema changes are applied explicitly through migrations and are not automatically applied during application startup.

### 4\. Run the API

powershell

```powershell
dotnet run
```

Swagger UI is available at `/swagger` when running in the Development environment.

### 5\. Configure and run tests

Integration tests require accessible SQL Server and Redis instances.

Configure the test infrastructure using environment variables:

powershell

```powershell
$env:AUTHAPI_TEST_SQL = "Server=localhost\SQLEXPRESS;Database=AuthenticationAPI_Test;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=True"

$env:AUTHAPI_TEST_REDIS = "localhost:6379"
```

Adjust these connection strings to match your test infrastructure.

Verify the configuration:

powershell

```powershell
$env:AUTHAPI_TEST_SQL
$env:AUTHAPI_TEST_REDIS
```

Run the test suite:

powershell

```powershell
cd ../.. # leave the src directory
dotnet test --logger "console;verbosity=normal"
```

Use a dedicated test database, separate from development and production databases.

### Configuration notes

- SQL Server and Redis are independently configurable.
- Docker Compose is optional; services can run locally or on separate infrastructure.
- Application secrets are managed through .NET User Secrets and should never be committed to source control.
- `TrustServerCertificate=True` is intended for appropriate development configurations. Production deployments should use properly configured TLS certificate validation.
- Use separate credentials, encryption keys and databases for production deployments.
- Never expose development infrastructure services publicly without appropriate network restrictions and authentication.


The shipped `appsettings.json` contains only placeholders. The application **refuses to start** while a required
secret is a placeholder, too short, or malformed (JWT key < 32 bytes, missing/invalid `Security:EncryptionKey`,
invalid limits, wildcard CORS, and — in Production — non-HTTPS `AppLink` or unconfigured SMTP).

## Features

| Area | Behaviour |
|---|---|
| Passwords | PBKDF2-HMAC-SHA512 (210 000 iterations, per-user 16-byte salt, constant-time compare). Legacy HMAC-SHA512 hashes still verify and are upgraded transparently at next login. Policy is configurable; default = length 10–128, common-password and email-name checks, no composition rules. |
| Access tokens | HS256 JWT, 15 min default, issuer/audience/lifetime/signature/algorithm validated, `kid` header, key rotation via `AppSettings:PreviousKeys`. Carries `sstamp` so revocation takes effect on already-issued tokens. |
| Refresh tokens | 256-bit random, only a SHA-256 hash is stored, single use, rotated each time, family revocation on reuse, absolute session cap, concurrent redemption yields exactly one winner. |
| Verification / reset | 256-bit random tokens, hash stored, atomic single-use redemption, expiry, per-IP/per-account limits, generic responses. Reset ends all sessions and does **not** log the user in. |
| Lockout | Atomic counters (Redis, per-instance fallback): per (account, IP), per account, per IP. Attempt is reserved *before* the password is checked. |
| MFA | TOTP (replay-protected), email OTP (existing, can be switched off), SMS OTP (opt-in, provider abstraction). Login returns a single-use challenge token; second factor cannot be attempted without having passed the password step. |
| Remember me / trusted device | Separate features. *Remember me* = longer refresh-token lifetime only. *Trusted device* (off by default) = opaque rotating credential that may replace the MFA step only; never for administrators; never bypasses the password. |
| Admin | Role change, disable/enable, unlock, MFA reset. Server-side policies; sensitive ones require authentication within the last 15 minutes; fully audited in SQL. |
| Notifications | Transactional outbox → background worker → SMTP/SMS provider. Retries with exponential backoff + jitter, dead-lettering, encrypted payloads scrubbed after delivery. |
| Observability | Serilog with correlation id, security events in SQL (`SecurityEvents`), `System.Diagnostics.Metrics` counters, `/health/live` and `/health/ready` (status word only). |

## Documentation

- [`docs/API.md`](docs/API.md) – endpoints, request/response examples, error conventions, token semantics, **breaking changes**
- [`docs/SECURITY.md`](docs/SECURITY.md) – audit findings, threat model decisions, SMS-MFA limitations, residual risks
- [`docs/REDIS.md`](docs/REDIS.md) – every Redis use, source of truth, failure policy
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) – configuration reference, secrets, migrations, deployment, workers, logging
- [`docs/TESTING.md`](docs/TESTING.md) – how to run unit/integration/mutation tests; what is and is not covered