# Security

This document describes the authentication service's security architecture, implemented security controls, threat-model decisions, operational requirements, and known residual risks.

It is intended to document the security properties and limitations of the running system, rather than provide a historical record of security changes.

## Authentication and Authorization

### Registration and Role Management

- Public registration always assigns the `Viewer` role.
- Client-supplied roles are never trusted or accepted during registration.
- Attempts to manipulate the registration role are audited.
- Role changes are restricted to administrators through `admin/role`.
- Authorization decisions are based on server-controlled identity and role claims.

### Email Verification

- Verification state is represented by the `IsVerified` JWT claim and reflects the account's actual verification state.
- Verification tokens are hashed at rest, bound to the account email, and redeemed atomically.
- Verification links are single-use.
- Unverified accounts cannot satisfy authorization requirements that depend on verified-user status.

### Multi-Factor Authentication

MFA supports TOTP and configurable email/SMS OTP methods.

The MFA login flow requires successful password authentication before a second-factor challenge can be completed.

- A successful password step issues a single-use, account-bound `challengeToken`.
- MFA verification requires this challenge token.
- Challenges are subject to an atomic five-attempt limit.
- TOTP time steps are recorded to prevent replay.
- OTP values are hashed using a server-side key.
- Email and SMS OTPs use uniformly distributed six-digit codes, have expiry and resend limits, and are attempt-limited.
- MFA setup and enable operations are rejected when MFA is already enabled.
- Enabling MFA requires password confirmation.
- Disabling MFA requires both password confirmation and a valid TOTP code.
- Disabling MFA revokes all active sessions.
- Phone-number enrolment and changes require password confirmation and, when MFA is enabled, a valid TOTP code.

### MFA Administration

The optional setting `Security:Mfa:RequireMfaForAdministrators` prevents administrators from disabling MFA.

This setting does not currently enforce MFA enrolment. Administrators who have not enrolled MFA are not automatically prevented from authenticating.

## Password Security

- Passwords are hashed using PBKDF2 with 210,000 iterations.
- Password verification uses fixed-time comparison.
- Existing password hashes can be upgraded through the password-hash upgrade path.
- The default minimum password length is 10 characters.
- Mandatory character-composition requirements are not enforced.

The password policy is designed to favour sufficient length and secure password storage over arbitrary composition rules.

## Session and Token Security

### Access Tokens

JWTs use HS256 signing with:

- Signature validation.
- Issuer and audience validation.
- Lifetime validation.
- Explicit algorithm restrictions through `ValidAlgorithms`.
- A minimum signing-key length of 32 bytes.
- Key-ID-based signing-key rotation.

Authenticated requests also validate the token's `sstamp` against the account's current session stamp.

The session stamp is checked against SQL, using a per-instance cache with a default lifetime of 15 seconds.

Setting `Security:SessionCacheSeconds=0` disables this cache and provides stricter revocation behaviour at the cost of an indexed database lookup for each authenticated request.

**Signing algorithm consideration:** HS256 is a symmetric signing scheme. Any service capable of validating these tokens also possesses the ability to mint them. If independent services need to validate tokens without acquiring signing privileges, asymmetric signing should be considered. This is an architectural decision and should be implemented as an explicit token-contract change.

### Refresh Tokens

Refresh tokens are managed as independent families per login session.

- Tokens are hashed before persistence.
- Rotation is performed atomically.
- Token reuse is detected and triggers session-family revocation.
- Full refresh-token values are never written to application logs.
- Revocation is persisted rather than relying on fire-and-forget operations.
- Refresh operations do not require an access token.

Strict reuse detection has an availability trade-off: concurrent refresh requests from the same legitimate client may be interpreted as replay and terminate the session.

### Session Revocation

The session stamp provides account-level invalidation of previously issued access tokens.

Password resets and MFA disable operations revoke active sessions.

Access tokens remain valid until expiry after ordinary logout. The maximum access-token lifetime therefore bounds the exposure window for a logged-out session.

## Account Protection and Rate Limiting

Authentication attempts are protected using atomic counters with the following scopes:

- Account + IP address.
- Account.
- IP address.

Counter keys use SHA-256 hashes of normalised email addresses and IP addresses to avoid storing plaintext personal information in Redis.

Default limits:

| Scope | Limit | Window |
| --- | --- | --- |
| Account + IP | 5 attempts | 15 minutes |
| Account | 50 attempts | 15 minutes |
| IP | 100 attempts | 15 minutes |

Counters are reserved atomically before password verification. Successful authentication releases the corresponding reservation.

Unknown email addresses are counted using the same mechanisms as existing accounts to reduce account enumeration and inconsistent lockout behaviour.

Administrators can unlock accounts by clearing the relevant account and account/IP counters.

Rate-limit violations return HTTP `429`.

### Lockout Trade-offs

The account-wide limit is deliberately higher than the account/IP limit. A low account-wide threshold would allow an attacker to lock out a victim simply by repeatedly attempting authentication.

The current threshold permits approximately 50 attempts per account within a 15-minute window, including attempts distributed across multiple IP addresses.

The system uses fixed-window counters rather than progressive delays.

Additional limitations:

- A distributed attacker may still make attempts against an account up to its account-wide limit.
- The per-IP limit can affect legitimate users sharing a NAT or corporate network.
- No CAPTCHA or proof-of-work mechanism is currently implemented.

## Account Recovery and Enumeration Protection

### Password Reset

- Password-reset tokens are hashed at rest.
- Tokens are bound to the account email.
- Redemption is atomic and single-use.
- A successful password reset revokes existing sessions.
- Requesting a password reset does not modify or revoke existing sessions.
- Password-reset requests return a generic success response regardless of whether the account exists.

### Verification and MFA Responses

Login, password-reset, and MFA endpoints use generic responses to reduce account enumeration.

Password verification for unknown accounts uses a dummy hash to reduce timing differences.

Registration remains an exception: an existing email address produces a response indicating that another email should be used. This is rate-limited by IP address and is documented as a residual enumeration risk.

Password-reset requests also perform an additional database write for existing accounts, leaving a small potential timing difference.

## Sensitive Data Protection

### Encryption at Rest

AES-256-GCM is used to encrypt sensitive values at rest, including:

- TOTP secrets.
- Sensitive outbox payloads.

The encryption key is provided through the required `Security:EncryptionKey` configuration setting.

### Token and OTP Storage

Authentication and recovery tokens are hashed rather than stored in plaintext.

OTP verification uses server-keyed hashing and fixed-time comparison.

Sensitive values, including passwords, access tokens, refresh tokens, OTPs, and TOTP secrets, must not be written to application logs.

### Logging and Error Handling

- Unexpected exceptions are handled through `ServiceGuard`.
- Raw exception messages are not returned to API clients.
- JWT failures are logged by failure type rather than sensitive token details.
- Email addresses are replaced with hashed identifiers in application logs.
- API errors use `application/problem+json` for unhandled failures.
- Business-error responses expose application-level messages rather than raw exception text.

## Infrastructure and Application Security

### HTTP Security

- Global request-body limit: 64 KB.
- Relevant controller request-body limit: 16 KB.
- CORS is restricted to explicitly configured origins.
- HSTS is enabled outside Development.
- `AllowedHosts` must be explicitly configured for each deployment.

### Configuration Validation

Security-sensitive configuration is validated using `IValidateOptions` and `ValidateOnStart`.

Invalid or placeholder configuration prevents application startup.

Email templates are resolved relative to the application base directory rather than the process working directory.

Clock skew is explicitly documented and configured as part of JWT validation.

### Email and SMS Delivery

Email operations are queued through the outbox.

Delivery is retried when the delivery provider is unavailable. The outbox provides at-least-once delivery semantics rather than guaranteed exactly-once delivery.

## Threat-Model Decisions

### Brute Force and Credential Stuffing

The combination of account/IP, account, and IP counters is intended to balance brute-force protection against denial-of-service through victim lockout.

Unknown accounts are counted identically to known accounts.

The trade-off is that distributed attacks can still make multiple attempts against an account within the account-wide threshold.

### Account Enumeration

Generic responses, dummy password verification, and uniform lockout handling reduce differences between existing and unknown accounts.

Registration remains a documented exception because it explicitly indicates when an email address is already registered.

### Refresh Token Theft and Replay

Refresh-token rotation uses strict reuse detection.

Reusing a previously consumed token revokes the associated token family. This prioritises replay detection over tolerance of concurrent refresh operations.

### JWT Signing

HS256 is retained for the current token contract. Because signing and verification use the same secret, the signing key must only be available to trusted components.

Asymmetric signing is the preferred direction if third-party or independently deployed services require token validation.

### Immediate Revocation

Session-stamp validation uses a per-instance cache with a default 15-second lifetime.

This introduces a potential revocation delay of up to the configured cache lifetime. Setting `Security:SessionCacheSeconds=0` removes that caching window.

### Dependency Failures

- **Redis unavailable:** Rate-limit counters fall back to per-instance memory. Limits remain enforced locally but are no longer consistent across application instances.
- **SQL unavailable:** Authenticated operations requiring database validation fail rather than granting access without validation.
- **Email/SMS provider unavailable:** Outbox delivery is retried. The initiating user-facing operation can still succeed.

## SMS MFA Limitations

SMS must not be considered phishing-resistant authentication.

SMS OTPs are vulnerable to:

- SIM swapping.
- Phone-number reassignment.
- SS7 and carrier interception.
- Malware.
- Real-time phishing relays.

SMS is a fallback second-factor method alongside TOTP. An attacker who controls the registered phone number may therefore satisfy the second-factor requirement without compromising the authenticator.

Email OTP has a similar fallback risk if the attacker controls the associated mailbox.

To require TOTP as the only second factor, configure:

- `Security:Mfa:EmailOtpEnabled=false`
- `SmsEnabled=false`

SMS codes are six digits, valid for 5–10 minutes, resend-throttled, server-keyed-hashed, single-use, and attempt-limited.

## Trusted Devices

Trusted devices are disabled by default.

When enabled:

- A successful MFA step may issue an opaque 256-bit credential.
- Only a hash of the credential is stored.
- The credential replaces the MFA step, never the password requirement.
- Trusted devices are not accepted for Administrators.
- Credentials rotate on each use.
- Replay of an old credential revokes the device.

Trusted-device credentials are delivered in the JSON response body. The service does not use cookies, so credential storage is the client's responsibility.

Browser applications should prefer an `HttpOnly` cookie managed by their own backend rather than storing credentials in browser-accessible storage.

Browser fingerprints and user-agent strings are not used as authentication proof. Device labels are user-supplied display text only.

## Known Residual Risks

The following limitations are known and are not currently addressed:

1. **At-least-once message delivery:** A crash between sending an email/SMS and committing its delivery state can result in duplicate messages.
2. **Redis Cluster compatibility:** `ResetPrefixAsync` uses `SCAN` over primaries and is not Redis-Cluster-safe.
3. **Distributed account guessing:** The account-wide threshold allows a limited number of guesses across multiple IP addresses within each window.
4. **Shared IP lockout:** The per-IP threshold can affect legitimate users behind a shared NAT.
5. **Password screening:** There is no CAPTCHA, proof-of-work, or comprehensive breached-password check beyond a small built-in list.
6. **Logout revocation:** Access tokens remain valid until expiry after logout.
7. **Proxy IP handling:** TestServer-only IP injection is used in tests. Real reverse-proxy behaviour and `ForwardedHeaders` configuration have not been fully tested.
8. **EF migration verification:** The EF migration and snapshot are hand-authored and should be verified using `dotnet ef` as described in `OPERATIONS.md`.
9. **Request-size handling:** HTTP 413 behaviour for oversized requests is not currently covered by a test.