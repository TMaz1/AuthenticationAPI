# API reference

Base path: `/api/auth`. JSON, camelCase, enums as strings. Request bodies are limited to 16 KB.
Business responses keep the historical envelope:

```json
{ "data": <payload|null>, "success": true, "message": "..." }
```

Unhandled errors and framework-level failures (401/403 with no body, malformed JSON, 500) are RFC 9457
`application/problem+json` with a `correlationId` extension; no stack traces, SQL text or exception messages.

| Status | Meaning |
|---|---|
| 200 | success |
| 400 | validation failure / invalid, expired or already-used token or code / wrong credentials |
| 401 | missing, invalid, expired or **revoked** access token |
| 403 | authenticated but not allowed (policy, unverified account token, disabled account, stale authentication for admin actions) |
| 404 | resource not found (admin endpoints), feature disabled, or hidden endpoint |
| 429 | throttled or rate limited; `Retry-After` header set |
| 500 | unexpected failure (`"An unexpected error occurred."`) |

Authentication: `Authorization: Bearer <accessToken>`.
Policies: **VerifiedUser** (token says `IsVerified=true`), **AdminVerified** (Administrator + verified),
**AdminRecentAuth** (AdminVerified + password/MFA authentication within `Security:AdminRecentAuthMinutes`; refreshing does not renew it).

## Endpoints

| Method & path | Auth | Purpose |
|---|---|---|
| POST `register` | anon | create account (role is always Viewer) |
| POST `login` | anon | password step; returns tokens or an MFA challenge |
| GET `user` | any token | current user |
| POST `verify-account` | anon | redeem verification token |
| POST `resend-verification` | any token | new verification email (limited) |
| POST `refresh-token` | anon (the refresh token is the credential) | rotate |
| POST `logout` | any token | revoke this user's refresh tokens |
| POST `sessions/revoke-all` | VerifiedUser | revoke refresh tokens, access tokens, trusted devices |
| POST `password-reset-request` | anon | always answers success |
| POST `reset-password` | anon | redeem reset token |
| GET `mfa/setup` | VerifiedUser | create pending TOTP secret, returns QR (base64 PNG) |
| POST `mfa/enable` | VerifiedUser | confirm TOTP **and password** |
| POST `mfa/verify` | anon + challenge | second step of login |
| POST `send-email-otp` | anon + challenge | email a one-time code |
| POST `mfa/send-sms-otp` | anon + challenge | SMS a one-time code (if enabled and phone verified) |
| POST `mfa/disable` | VerifiedUser | requires password **and** TOTP |
| POST `mfa/sms/enroll`, `mfa/sms/confirm` | VerifiedUser | verify a phone number |
| GET `devices`, DELETE `devices/{id}` | VerifiedUser | list / revoke trusted devices |
| POST `admin/unlock` | AdminVerified | clear lockout counters |
| POST `admin/disable`, `admin/enable`, `admin/role`, `mfa/admin/reset` | AdminRecentAuth | account administration |
| POST `email/test/all?to=` | AdminVerified, **Development only** | queue sample emails |
| GET `protected-resource` | VerifiedUser | sample |
| GET `/health/live`, `/health/ready` | anon | status word only |

## Examples (all values are fictional)

### Register
```http
POST /api/auth/register
{ "email":"ada@example.com","password":"correct horse battery staple","confirmPassword":"correct horse battery staple",
  "firstName":"Ada","lastName":"Lovelace","role":"Administrator" }
```
```json
{ "data": true, "success": true, "message": "Successfully registered user with email 'ada@example.com'" }
```
`role` is accepted for compatibility but **ignored**; the account is a Viewer and an audit event `register.role_ignored` is stored.
A verification email is queued in the same SQL transaction as the user row.

### Login (no MFA)
```http
POST /api/auth/login
{ "email":"ada@example.com","password":"…","rememberMe":false }
```
```json
{ "data": { "user": { "id": 7, "email":"ada@example.com", "...": "..." },
            "token":"eyJ…", "refreshToken":"q3u0…43chars", "mfa": { "requiresMfa": false, "availableMethods":["Totp","Email"] } },
  "success": true, "message": "Successfully logged in user with email 'ada@example.com'" }
```
Wrong password **and** unknown email both return `400 {"success":false,"message":"Incorrect email or password."}`.
After too many failures: `429` + `Retry-After`.
An unverified account receives an access token with `IsVerified=false` and **no** refresh token.

### Login with MFA
```json
{ "data": { "user": {…}, "mfa": { "requiresMfa": true, "selectedMethod":"Totp",
            "availableMethods":["Totp","Email","Sms"], "challengeToken":"Zk3…43chars" } },
  "success": true, "message": "MFA required. Please verify using your authenticator app." }
```
```http
POST /api/auth/mfa/verify
{ "email":"ada@example.com","otp":"123456","method":"Totp","challengeToken":"Zk3…","trustThisDevice":false }
```
Returns the same shape as a successful login. The challenge is single-use, expires after 5 minutes, is bound to the
account, and allows 5 attempts in total (then `429`; sign in again).
For email/SMS first call `send-email-otp` / `mfa/send-sms-otp` with `{ "email", "challengeToken" }`, then verify with `"method":"Email"` or `"Sms"`.

### Refresh
```http
POST /api/auth/refresh-token
{ "token":"q3u0…" }
```
Returns a new `token` and a **new** `refreshToken`. Presenting an already-used refresh token returns 400 and
revokes the whole family (the legitimate holder must sign in again). Two simultaneous refreshes with the same
token: one succeeds, the other triggers that same reuse response — clients must serialise refreshes.

### Password reset
`password-reset-request` → `200 "If an account exists for that email, a password reset link has been sent."` (always).
The emailed link carries `?token=…`; then:
```http
POST /api/auth/reset-password
{ "email":"ada@example.com","token":"…","newPassword":"…","confirmPassword":"…" }
```
On success all sessions, refresh tokens and trusted devices are revoked, lockout is cleared, a notification email is
queued, and **no tokens are returned**.

### MFA enrolment / disable
```http
GET  /api/auth/mfa/setup                                   → QR image (base64) in data
POST /api/auth/mfa/enable   { "otpCode":"123456","password":"…" }
POST /api/auth/mfa/disable  { "password":"…","otpCode":"123456" }   → ends every session
```
### SMS
```http
POST /api/auth/mfa/sms/enroll   { "phoneNumber":"+14155550123","password":"…","otpCode":"123456" }  (otpCode required if MFA already enabled)
POST /api/auth/mfa/sms/confirm  { "code":"654321" }
```
### Admin
```http
POST /api/auth/admin/role { "email":"ada@example.com","role":"Editor" }
```
Administrators cannot change their own role or disable themselves.

## Token lifetimes and revocation

| Artifact | Default | Revoked by |
|---|---|---|
| Access token (JWT) | 15 min (`AppSettings:AccessTokenExpiration`), skew 30 s | security-stamp rotation: password reset, MFA disable/reset, role change, disable, `sessions/revoke-all` (≤ `Security:SessionCacheSeconds`, default 15 s, on other instances) |
| Refresh token | 7 days; 30 with `rememberMe`; absolute cap 90 days from authentication | use, reuse detection, logout, password reset, disable, MFA reset |
| Verification token | 24 h | use, replacement |
| Reset token | 30 min | use, replacement |
| MFA challenge | 5 min / 5 attempts | use, expiry |
| Email/SMS OTP | 5 min, 30 s resend cooldown | use, expiry, new challenge |
| Trusted device | off by default; 30 days absolute, rotates on every use | revoke, password reset, MFA change, replay detection |

`logout` revokes refresh tokens only: an already-issued access token lives until it expires (≤ 15 min). Use
`sessions/revoke-all` for immediate effect.