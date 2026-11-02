using AuthenticationAPI.Configuration;
using AuthenticationAPI.Dtos;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Tests.Unit;

public static class T
{
    public static IOptions<SecurityOptions> Sec(Action<SecurityOptions>? tweak = null)
    {
        var o = new SecurityOptions { EncryptionKey = Convert.ToBase64String(new byte[32].Select((_, i) => (byte)(i + 1)).ToArray()) };
        o.Password.Pbkdf2Iterations = 100_000; // minimum allowed; keeps unit tests fast
        tweak?.Invoke(o);
        return Options.Create(o);
    }

    public static JwtSettings Jwt(Action<JwtSettings>? tweak = null)
    {
        var j = new JwtSettings
        {
            Key = new string('k', 48),
            Issuer = "https://issuer.test",
            Audience = "https://audience.test",
            ClockSkewSeconds = 0
        };
        tweak?.Invoke(j);
        return j;
    }
}

public sealed class FakeTime(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
}
