
# Changelog

## Security and Authentication Overhaul

Major security improvements across authentication, authorization, MFA, session management, account recovery, and application configuration.

### Security

- Prevented privilege escalation through client-supplied registration roles. New accounts are assigned the `Viewer` role.
- Hardened MFA authentication with password-bound login challenges, attempt limits, TOTP replay protection, and secure OTP handling.
- Secured MFA enrolment and disable operations with additional password and OTP verification.
- Reworked refresh-token management with hashed storage, independent session families, atomic rotation, and reuse detection.
- Upgraded password hashing to PBKDF2 (210,000 iterations) with fixed-time verification and hash upgrading.
- Introduced atomic, multi-scope authentication rate limiting and improved account enumeration protection.
- Secured password-reset and email-verification tokens with hashing, account binding, and atomic redemption.
- Added AES-256-GCM encryption for TOTP secrets and sensitive outbox payloads.
- Restricted email testing to administrators in Development.
- Improved error handling and logging to prevent sensitive information and exception details from being exposed.

### Changed

- `mfa/verify` and `send-email-otp` now require a login `challengeToken`.
- `mfa/enable` now requires `password`; `mfa/disable` requires `{ password, otpCode }`.
- MFA setup and enable operations are rejected when MFA is already enabled.
- `refresh-token` no longer requires a bearer access token.
- Rate-limit and lockout responses now return HTTP `429` instead of `400`.
- Password-reset requests return a generic success response regardless of account existence.
- The `IsVerified` JWT claim now reflects the account's actual verification state.
- Default password policy now requires a minimum length of 10 characters without mandatory character composition.
- New accounts use case-folded email addresses.
- Unhandled API errors now return `application/problem+json`.

### Removed

- Removed the generic `IDistributedCache`-based cache service. Its former callers have been replaced with dedicated implementations appropriate for security-sensitive data.

### Configuration and Deployment

- Added required `Security:EncryptionKey` configuration.
- Added startup validation for security-sensitive configuration.
- Added request-body limits, explicit-origin CORS, and HSTS outside Development.
- `AllowedHosts` must be explicitly configured for each deployment.

### Migration Notes

This release invalidates all previously issued refresh tokens, email verification links, and password reset links.

Previously issued access tokens are also rejected because they lack the required `sstamp` claim. They will naturally expire within the existing maximum access-token lifetime of 15 minutes.

**All users must authenticate again after deployment.**

See [SECURITY.md](./docs/SECURITY.md) for the security architecture, threat-model decisions, operational considerations, and known residual risks.