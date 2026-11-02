using System.Security.Cryptography;
using System.Text;
using AuthenticationAPI.Configuration;
using AuthenticationAPI.Models;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Password;

public sealed record PasswordHashResult(byte[] Hash, byte[] Salt, int Version, int Iterations);
public sealed record PasswordVerification(bool Verified, bool NeedsUpgrade);

public interface IPasswordService
{
    /// <summary>Returns human-readable policy violations; empty when the password is acceptable.</summary>
    IReadOnlyList<string> Validate(string password, string? email = null);
    PasswordHashResult Hash(string password);
    PasswordVerification Verify(string password, User user);
    /// <summary>Performs a hash comparison of equivalent cost so unknown-account logins take comparable time.</summary>
    void VerifyDummy(string password);
}

public sealed class PasswordService(IOptions<SecurityOptions> options) : IPasswordService
{
    public const int CurrentVersion = 2;
    private const int SaltBytes = 16;
    private const int HashBytes = 64;
    private readonly PasswordPolicyOptions _policy = options.Value.Password;

    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "password123", "passw0rd", "12345678", "123456789", "1234567890", "qwerty123",
        "qwertyuiop", "iloveyou", "admin1234", "welcome123", "letmein123", "abc12345", "11111111", "000000000",
        "1q2w3e4r5t", "changeme123", "p@ssw0rd", "p@ssword1", "password!", "administrator"
    };

    private readonly Lazy<byte[]> _dummySalt = new(() => RandomNumberGenerator.GetBytes(SaltBytes));

    public IReadOnlyList<string> Validate(string password, string? email = null)
    {
        var errors = new List<string>();
        if (password.Length < _policy.MinLength) errors.Add($"Password must be at least {_policy.MinLength} characters long.");
        if (password.Length > _policy.MaxLength) errors.Add($"Password must be at most {_policy.MaxLength} characters long.");
        if (_policy.RequireUppercase && !password.Any(char.IsUpper)) errors.Add("Password must contain an uppercase letter.");
        if (_policy.RequireLowercase && !password.Any(char.IsLower)) errors.Add("Password must contain a lowercase letter.");
        if (_policy.RequireDigit && !password.Any(char.IsDigit)) errors.Add("Password must contain a digit.");
        if (_policy.RequireSpecial && !password.Any(c => !char.IsLetterOrDigit(c))) errors.Add("Password must contain a special character.");
        if (_policy.BlockCommonPasswords && Common.Contains(password)) errors.Add("Password is too common.");

        if (!string.IsNullOrWhiteSpace(email))
        {
            var local = email.Split('@')[0];
            if (local.Length >= 4 && password.Contains(local, StringComparison.OrdinalIgnoreCase))
                errors.Add("Password must not contain your email name.");
        }

        return errors;
    }

    public PasswordHashResult Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var iterations = _policy.Pbkdf2Iterations;
        var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA512, HashBytes);
        return new PasswordHashResult(hash, salt, CurrentVersion, iterations);
    }

    public PasswordVerification Verify(string password, User user)
    {
        var bytes = Encoding.UTF8.GetBytes(password);

        if (user.PasswordHashVersion >= CurrentVersion)
        {
            var iterations = user.PasswordHashIterations ?? _policy.Pbkdf2Iterations;
            var computed = Rfc2898DeriveBytes.Pbkdf2(bytes, user.PasswordSalt, iterations, HashAlgorithmName.SHA512, user.PasswordHash.Length);
            var ok = CryptographicOperations.FixedTimeEquals(computed, user.PasswordHash);
            return new PasswordVerification(ok, ok && iterations < _policy.Pbkdf2Iterations);
        }

        // legacy v1: HMAC-SHA512 keyed with the stored salt. Verified here, upgraded by the caller after success.
        using var hmac = new HMACSHA512(user.PasswordSalt);
        var legacy = hmac.ComputeHash(bytes);
        var legacyOk = CryptographicOperations.FixedTimeEquals(legacy, user.PasswordHash);
        return new PasswordVerification(legacyOk, legacyOk);
    }

    public void VerifyDummy(string password)
    {
        _ = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), _dummySalt.Value, _policy.Pbkdf2Iterations, HashAlgorithmName.SHA512, HashBytes);
    }
}
