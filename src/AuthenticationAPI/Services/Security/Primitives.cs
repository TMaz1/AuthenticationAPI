using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthenticationAPI.Services.Security;

public static partial class Identifiers
{
    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    /// <summary>Stable, non-reversible, low-cardinality-safe identifier for use in Redis keys and logs (no PII).</summary>
    public static string Hash(string value, int hexChars = 32)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(digest)[..hexChars].ToLowerInvariant();
    }

    public static string EmailId(string email) => "e:" + Hash(NormalizeEmail(email), 12);

    public static string MaskPhone(string? phone) =>
        string.IsNullOrEmpty(phone) || phone.Length < 4 ? "***" : "***" + phone[^4..];

    [GeneratedRegex(@"^\+[1-9][0-9]{7,14}$")]
    private static partial Regex E164Regex();
    public static bool IsE164(string? phone) => phone is not null && E164Regex().IsMatch(phone);

    [GeneratedRegex(@"^[A-Za-z0-9_-]{20,128}$")]
    private static partial Regex OpaqueTokenRegex();
    /// <summary>Cheap shape check done before any hashing or database access.</summary>
    public static bool LooksLikeOpaqueToken(string? token) => token is not null && OpaqueTokenRegex().IsMatch(token);

    [GeneratedRegex(@"^[0-9]{6}$")]
    private static partial Regex SixDigitRegex();
    public static bool IsSixDigitCode(string? code) => code is not null && SixDigitRegex().IsMatch(code);
}

public static class TokenGenerator
{
    /// <summary>256-bit CSPRNG token, base64url without padding (43 chars).</summary>
    public static string NewOpaqueToken(int bytes = 32) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Uniform 6-digit code from a CSPRNG.</summary>
    public static string NewSixDigitCode() => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
}

public static class TokenHasher
{
    /// <summary>SHA-256 hex. Appropriate only for high-entropy random tokens (not for passwords or short codes).</summary>
    public static string Hash(string rawToken) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken))).ToLowerInvariant();

    public static bool FixedTimeEquals(string? a, string? b)
    {
        if (a is null || b is null) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
    }
}

public static class OtpGenerator
{
    /// <summary>
    /// Generates a uniformly random 6-digit OTP. (The previous implementation rejected codes with repeated digits, which
    /// only shrank the code space without improving security.)
    /// </summary>
    public static string GenerateOTP() => TokenGenerator.NewSixDigitCode();
}

public interface ISecretProtector
{
    string Protect(string plaintext, string purpose);
    /// <summary>Throws CryptographicException if the value was tampered with, protected for another purpose, or uses another key.</summary>
    string Unprotect(string protectedValue, string purpose);
    bool IsProtected(string? value);
    /// <summary>HMAC-SHA256 (hex) under the server key; for hashing low-entropy codes so a DB leak does not allow offline guessing.</summary>
    string KeyedHash(string purpose, string data);
}

public sealed class AesGcmSecretProtector : ISecretProtector
{
    private const string Prefix = "v1:";
    private readonly byte[] _key;

    public AesGcmSecretProtector(string base64Key)
    {
        _key = Convert.FromBase64String(base64Key);
        if (_key.Length != 32) throw new ArgumentException("Encryption key must be 32 bytes.", nameof(base64Key));
    }

    public bool IsProtected(string? value) => value is not null && value.StartsWith(Prefix, StringComparison.Ordinal);

    public string Protect(string plaintext, string purpose)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var data = Encoding.UTF8.GetBytes(plaintext);
        var cipher = new byte[data.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, data, cipher, tag, Encoding.UTF8.GetBytes(purpose));

        var blob = new byte[12 + 16 + cipher.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, 12);
        Buffer.BlockCopy(tag, 0, blob, 12, 16);
        Buffer.BlockCopy(cipher, 0, blob, 28, cipher.Length);
        return Prefix + Convert.ToBase64String(blob);
    }

    public string Unprotect(string protectedValue, string purpose)
    {
        if (!IsProtected(protectedValue)) throw new CryptographicException("Value is not protected.");
        var blob = Convert.FromBase64String(protectedValue[Prefix.Length..]);
        if (blob.Length < 28) throw new CryptographicException("Malformed protected value.");

        var nonce = blob.AsSpan(0, 12);
        var tag = blob.AsSpan(12, 16);
        var cipher = blob.AsSpan(28);
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(purpose));
        return Encoding.UTF8.GetString(plain);
    }

    public string KeyedHash(string purpose, string data)
    {
        using var hmac = new HMACSHA256(_key);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(purpose + ":" + data))).ToLowerInvariant();
    }
}
