using System.Security.Cryptography;
using AuthenticationAPI.Services.Security;
using FsCheck.Xunit;
using Xunit;

namespace AuthenticationAPI.Tests.Unit;

[Trait("Category", "Unit")]
public class PrimitivesTests
{
    private static readonly string Key = Convert.ToBase64String(new byte[32].Select((_, i) => (byte)(i + 7)).ToArray());

    [Fact]
    public void Opaque_tokens_are_unique_urlsafe_and_long()
    {
        var set = new HashSet<string>();
        for (var i = 0; i < 500; i++)
        {
            var t = TokenGenerator.NewOpaqueToken();
            Assert.Equal(43, t.Length);
            Assert.True(Identifiers.LooksLikeOpaqueToken(t));
            Assert.True(set.Add(t));
        }
    }

    [Fact]
    public void Six_digit_codes_are_six_digits()
    {
        for (var i = 0; i < 2000; i++) Assert.True(Identifiers.IsSixDigitCode(OtpGenerator.GenerateOTP()));
    }

    [Fact]
    public void Six_digit_codes_include_repeated_digits_unlike_the_old_generator()
    {
        // the old generator never produced 3+ identical digits; a uniform generator will within a few thousand draws
        Assert.Contains(Enumerable.Range(0, 20000).Select(_ => OtpGenerator.GenerateOTP()), c => c.Distinct().Count() <= 2);
    }

    [Property]
    public bool Hash_is_deterministic_hex64(FsCheck.NonEmptyString s)
    {
        var a = TokenHasher.Hash(s.Get);
        return a == TokenHasher.Hash(s.Get) && a.Length == 64 && a.All(Uri.IsHexDigit) && a == a.ToLowerInvariant();
    }

    [Property]
    public bool Opaque_token_validator_rejects_any_string_with_illegal_characters(FsCheck.NonEmptyString s) =>
        !Identifiers.LooksLikeOpaqueToken(s.Get + "!");

    [Theory]
    [InlineData("+14155550123", true)]
    [InlineData("14155550123", false)]
    [InlineData("+0123456789", false)]
    [InlineData("+1415555012345678", false)]
    [InlineData("+1 415 555 0123", false)]
    [InlineData("", false)]
    public void E164(string phone, bool expected) => Assert.Equal(expected, Identifiers.IsE164(phone));

    [Theory]
    [InlineData("", false)]
    [InlineData("short", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaa==", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaa", true)]
    public void Token_shape(string token, bool expected) => Assert.Equal(expected, Identifiers.LooksLikeOpaqueToken(token));

    [Fact]
    public void Email_normalisation_is_case_and_whitespace_insensitive()
    {
        Assert.Equal(Identifiers.NormalizeEmail("  Bob@Example.COM "), Identifiers.NormalizeEmail("bob@example.com"));
        Assert.Equal(Identifiers.EmailId("BOB@example.com"), Identifiers.EmailId(" bob@example.com"));
        Assert.DoesNotContain("bob", Identifiers.EmailId("bob@example.com"));
    }

    [Fact]
    public void Fixed_time_equals_handles_null_and_length_mismatch()
    {
        Assert.True(TokenHasher.FixedTimeEquals("abc", "abc"));
        Assert.False(TokenHasher.FixedTimeEquals("abc", "abd"));
        Assert.False(TokenHasher.FixedTimeEquals("abc", "abcd"));
        Assert.False(TokenHasher.FixedTimeEquals(null, "abc"));
        Assert.False(TokenHasher.FixedTimeEquals("abc", null));
    }

    [Fact]
    public void Protector_round_trips_and_does_not_store_plaintext()
    {
        var p = new AesGcmSecretProtector(Key);
        var protectedValue = p.Protect("JBSWY3DPEHPK3PXP", "mfa-secret");
        Assert.StartsWith("v1:", protectedValue);
        Assert.DoesNotContain("JBSWY3DPEHPK3PXP", protectedValue);
        Assert.True(p.IsProtected(protectedValue));
        Assert.Equal("JBSWY3DPEHPK3PXP", p.Unprotect(protectedValue, "mfa-secret"));
        Assert.NotEqual(protectedValue, p.Protect("JBSWY3DPEHPK3PXP", "mfa-secret")); // fresh nonce each time
    }

    [Fact]
    public void Protector_rejects_tampering_wrong_purpose_and_wrong_key()
    {
        var p = new AesGcmSecretProtector(Key);
        var v = p.Protect("secret", "purpose-a");

        Assert.ThrowsAny<CryptographicException>(() => p.Unprotect(v, "purpose-b"));

        var raw = Convert.FromBase64String(v[3..]);
        raw[^1] ^= 0x01;
        Assert.ThrowsAny<CryptographicException>(() => p.Unprotect("v1:" + Convert.ToBase64String(raw), "purpose-a"));

        var other = new AesGcmSecretProtector(Convert.ToBase64String(new byte[32]));
        Assert.ThrowsAny<CryptographicException>(() => other.Unprotect(v, "purpose-a"));
        Assert.ThrowsAny<CryptographicException>(() => p.Unprotect("plain-text", "purpose-a"));
    }

    [Fact]
    public void Keyed_hash_depends_on_purpose_data_and_key()
    {
        var p = new AesGcmSecretProtector(Key);
        Assert.Equal(p.KeyedHash("a", "123456"), p.KeyedHash("a", "123456"));
        Assert.NotEqual(p.KeyedHash("a", "123456"), p.KeyedHash("b", "123456"));
        Assert.NotEqual(p.KeyedHash("a", "123456"), p.KeyedHash("a", "123457"));
        Assert.NotEqual(p.KeyedHash("a", "123456"), new AesGcmSecretProtector(Convert.ToBase64String(new byte[32])).KeyedHash("a", "123456"));
    }

    [Fact]
    public void Protector_rejects_wrong_key_length() =>
        Assert.Throws<ArgumentException>(() => new AesGcmSecretProtector(Convert.ToBase64String(new byte[16])));
}
