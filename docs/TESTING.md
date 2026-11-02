# Testing

```
tests/AuthenticationAPI.Tests/
  Unit/         no infrastructure: passwords, primitives/crypto, JWT, throttling, options validation, backoff, authorization handler
  Integration/  WebApplicationFactory against a REAL SQL Server database (created per fixture, migrated with the real migrations, dropped afterwards)
```

Traits: `Category=Unit`, `Category=Integration`.

## Run

```bash
scripts/test.sh unit                                  # format check + Release build + unit tests

SA_PASSWORD='<local>' docker compose up -d
export AUTHAPI_TEST_SQL='Server=localhost,1433;User Id=sa;Password=<local>;TrustServerCertificate=true;Encrypt=false'   # no Database= part
export AUTHAPI_TEST_REDIS=localhost:6379               # optional; enables the Redis Lua-script tests
scripts/test.sh all
```

Without `AUTHAPI_TEST_SQL` every SQL integration test is reported as **Skipped** (never as passed); without
`AUTHAPI_TEST_REDIS` the Redis tests are skipped. CI sets both and fails if any integration test was skipped.

## Design

- SQL Server semantics are real (atomic conditional updates, unique/filtered indexes, check constraint, cascades). No in-memory provider anywhere.
- The component under test is never mocked. Only the *delivery edges* are fakes: `IEmailSender`, `ISmsSender`, and the rate-limit store in HTTP tests (a real in-memory implementation; the Redis implementation is tested separately, and the Redis-down path uses a real multiplexer pointed at a closed port).
- The outbox is pumped explicitly (`ProcessBatchAsync`), background timers are disabled — no sleeps. Expiry is tested by editing timestamps in the database.
- Each test uses fresh users and a distinct client IP (`X-Test-Ip`, honoured only by a test middleware) so throttle counters never leak between tests.
- Concurrency tests fire parallel HTTP requests and assert exactly-one-winner (verification, reset, refresh, MFA verify, outbox workers).

## Security and Reliability Test Coverage

Invalid/expired/tampered/replayed tokens ✔ · concurrent refresh ✔ · concurrent reset/verify ✔ · concurrent MFA ✔ · lockout thresholds & concurrent failures ✔ ·
cross-user/device misuse ✔ · authorization bypass ✔ · revocation on password change/disable/admin action ✔ · Redis outage ✔ (store-level, unit) ·
provider failures ✔ (outbox) · worker retry/duplicate/restart(lease) ✔ · malformed input ✔ (limited).

**Not covered / known gaps:** SQL Server timeout/transaction-failure injection; oversized-body (413) behaviour; reverse-proxy
forwarded headers; Redis outage *during* an HTTP request end-to-end; load/performance tests; browser/client behaviour.

## Advanced Testing Strategies

FsCheck properties cover hashing, token-shape validation and back-off bounds/monotonicity.
Mutation testing is separate from the fast run: `dotnet tool install -g dotnet-stryker && dotnet stryker --config-file stryker-config.json`
(also `.github/workflows/mutation.yml`, manual/weekly). It targets `Services/Security`, `Services/Password`, JWT, outbox, options and startup,
using unit tests only, so **mutants in `AuthService`/`MfaService`/`RefreshTokenService` are not killed by it** — those are guarded by the integration suite.
No mutation score has been measured.
