using System.Diagnostics.Metrics;

namespace AuthenticationAPI.Services.Security;

/// <summary>
/// Operational counters (System.Diagnostics.Metrics). Tags are drawn only from fixed, small sets;
/// attacker-controlled values (emails, IPs, tokens) are never used as tag values.
/// </summary>
public static class AuthMetrics
{
    public const string MeterName = "AuthenticationAPI";
    private static readonly Meter Meter = new(MeterName, "1.0");

    public static readonly Counter<long> LoginOutcome = Meter.CreateCounter<long>("auth.login.outcome");
    public static readonly Counter<long> RefreshOutcome = Meter.CreateCounter<long>("auth.refresh.outcome");
    public static readonly Counter<long> RedisFallback = Meter.CreateCounter<long>("auth.redis.fallback");
    public static readonly Counter<long> OutboxSent = Meter.CreateCounter<long>("auth.outbox.sent");
    public static readonly Counter<long> OutboxRetried = Meter.CreateCounter<long>("auth.outbox.retried");
    public static readonly Counter<long> OutboxDeadLettered = Meter.CreateCounter<long>("auth.outbox.dead_lettered");
}
