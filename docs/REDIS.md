# Redis Architecture and Usage

Redis is used for exactly one purpose: **atomic, expiring counters** for lockout and rate limiting, where several API
instances must agree and the data is ephemeral. Everything else that needs durability or one-time semantics
(refresh tokens, reset/verification tokens, MFA challenges, OTP codes, trusted devices, outbox, audit) lives in
SQL Server with conditional-update atomicity. Redis is never the only record of a security event.

| Use | Keys (prefix `Security:Redis:KeyPrefix`, default `authapi:`) | Source of truth | Expiry | If Redis is down |
|---|---|---|---|---|
| Login throttle | `login:ai:<h24(email)>:<h16(ip)>`, `login:a:<h24(email)>`, `login:ip:<h16(ip)>` | the counters themselves (ephemeral) | `Lockout:WindowMinutes` (set on first increment, re-set if a key ever lacks a TTL) | per-instance in-memory counters; limits still enforced, no fail-open |
| Endpoint rate limits | `rl:<policy>:<h24(identifier)>` | counters | rule `WindowSeconds` | same fallback |

- `h<N>` = first N hex chars of SHA-256 of the normalised value: no emails or IPs in keys, bounded key length, no cross-user collisions beyond 2^-96.
- Increment = one Lua script (`INCR` + `PEXPIRE` when new) → atomic. Release = Lua `GET`/`DECR` floored at 0. No read-modify-write, no distributed locks.
- Memory is bounded by TTLs. The in-memory fallback is capped (100 000 entries, expired-first then soonest-to-expire eviction).
- Connection: `AbortOnConnectFail=false` (the API starts without Redis), `ConnectTimeoutMs`/`OperationTimeoutMs` configurable. Use TLS/auth in the connection string (`host:6380,password=…,ssl=true`); never commit it.
- Health: `/health/ready` reports Redis as **Degraded** (HTTP 200), not Unhealthy.
- Metrics: `auth.redis.fallback` counts operations served from memory.
- Not Redis-Cluster-safe in one place: admin unlock uses `SCAN` over primaries to clear per-(account, IP) counters.
- Recommended server config: `maxmemory` with `volatile-ttl`, no persistence needed (see `docker-compose.yml`).
