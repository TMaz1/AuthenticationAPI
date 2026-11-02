using System.Security.Cryptography;
using System.Text;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services.Password;
using Xunit;

namespace AuthenticationAPI.Tests.Unit;

[Trait("Category", "Unit")]
public class PasswordServiceTests
{
    private static PasswordService Svc(Action<AuthenticationAPI.Configuration.SecurityOptions>? t = null) => new(T.Sec(t));

    private static User UserFrom(PasswordHashResult h) => new()
    {
        Email = "a@example.com", FirstName = "A", PasswordHash = h.Hash, PasswordSalt = h.Salt,
        PasswordHashVersion = h.Version, PasswordHashIterations = h.Iterations
    };

    [Fact]
    public void Hash_then_verify_succeeds_and_wrong_password_fails()
    {
        var s = Svc();
        var user = UserFrom(s.Hash("correct horse battery"));
        Assert.True(s.Verify("correct horse battery", user).Verified);
        Assert.False(s.Verify("correct horse batterx", user).Verified);
        Assert.False(s.Verify("", user).Verified);
    }

    [Fact]
    public void Same_password_yields_different_salt_and_hash()
    {
        var s = Svc();
        var a = s.Hash("same password 123");
        var b = s.Hash("same password 123");
        Assert.NotEqual(a.Salt, b.Salt);
        Assert.NotEqual(a.Hash, b.Hash);
        Assert.Equal(2, a.Version);
    }

    [Fact]
    public void Legacy_hmac_hash_verifies_and_is_flagged_for_upgrade()
    {
        var salt = RandomNumberGenerator.GetBytes(128);
        using var hmac = new HMACSHA512(salt);
        var legacy = new User
        {
            Email = "old@example.com", FirstName = "Old", PasswordSalt = salt,
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes("Legacy#Pass1")), PasswordHashVersion = 1
        };
        var s = Svc();

        var ok = s.Verify("Legacy#Pass1", legacy);
        Assert.True(ok.Verified);
        Assert.True(ok.NeedsUpgrade);

        var bad = s.Verify("Legacy#Pass2", legacy);
        Assert.False(bad.Verified);
        Assert.False(bad.NeedsUpgrade);
    }

    [Fact]
    public void Hash_with_fewer_iterations_than_policy_needs_upgrade()
    {
        var low = Svc(o => o.Password.Pbkdf2Iterations = 100_000);
        var user = UserFrom(low.Hash("password for upgrade"));
        var high = Svc(o => o.Password.Pbkdf2Iterations = 150_000);
        var v = high.Verify("password for upgrade", user);
        Assert.True(v.Verified);
        Assert.True(v.NeedsUpgrade);
    }

    [Theory]
    [InlineData("short", false)]
    [InlineData("long enough passphrase", true)]
    [InlineData("password123", false)]   // 11 chars but on the common-password list
    [InlineData("Password1", false)]     // 9 chars, below the default minimum of 10
    public void Default_policy(string password, bool valid) => Assert.Equal(valid, Svc().Validate(password).Count == 0);

    [Fact]
    public void Composition_rules_are_enforced_only_when_configured()
    {
        Assert.Empty(Svc().Validate("alllowercaseletters"));
        var strict = Svc(o => { o.Password.RequireUppercase = true; o.Password.RequireDigit = true; o.Password.RequireSpecial = true; });
        Assert.NotEmpty(strict.Validate("alllowercaseletters"));
        Assert.Empty(strict.Validate("Abcdefghij1!"));
    }

    [Fact]
    public void Password_containing_email_name_is_rejected()
    {
        Assert.NotEmpty(Svc().Validate("jonathan-is-great", "jonathan@example.com"));
        Assert.Empty(Svc().Validate("unrelated passphrase", "jonathan@example.com"));
    }

    [Fact]
    public void Excessive_length_is_rejected() => Assert.NotEmpty(Svc().Validate(new string('a', 129)));
}
