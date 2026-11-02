using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Enums;
using AuthenticationAPI.Services.Token;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthenticationAPI.Tests.Unit;

[Trait("Category", "Unit")]
public class JwtTokenTests
{
    private static User U(bool active) => new()
    {
        Id = 42,
        Email = "a@example.com",
        FirstName = "A",
        PasswordHash = [1],
        PasswordSalt = [1],
        IsActive = active,
        Role = RoleType.Editor
    };

    private static ClaimsPrincipal Validate(string token, JwtSettings s) =>
        new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, TokenValidation.Create(s), out _);

    [Fact]
    public void Issued_token_validates_and_carries_expected_claims()
    {
        var s = T.Jwt();
        var token = new JwtTokenService(Options.Create(s)).CreateAccessToken(U(true), DateTime.UtcNow, "pwd mfa");
        var p = Validate(token, s);

        Assert.Equal("42", p.FindFirst("sub")!.Value);
        Assert.Equal("true", p.FindFirst("IsVerified")!.Value);
        Assert.Equal("Editor", p.FindFirst(ClaimTypes.Role)!.Value);
        Assert.Equal("pwd mfa", p.FindFirst("amr")!.Value);
        Assert.False(string.IsNullOrEmpty(p.FindFirst("sstamp")!.Value));
        Assert.False(string.IsNullOrEmpty(p.FindFirst("jti")!.Value));
        Assert.True(long.Parse(p.FindFirst("auth_time")!.Value) > 0);
    }

    [Fact]
    public void Unverified_user_token_says_IsVerified_false()
    {
        // regression: unverified accounts used to receive IsVerified=true and passed the VerifiedUser policy
        var s = T.Jwt();
        var token = new JwtTokenService(Options.Create(s)).CreateAccessToken(U(false), DateTime.UtcNow, "pwd");
        Assert.Equal("false", Validate(token, s).FindFirst("IsVerified")!.Value);
    }

    [Fact]
    public void Token_signed_with_another_key_is_rejected()
    {
        var token = new JwtTokenService(Options.Create(T.Jwt(j => j.Key = new string('x', 48)))).CreateAccessToken(U(true), DateTime.UtcNow, "pwd");
        Assert.ThrowsAny<SecurityTokenException>(() => Validate(token, T.Jwt()));
    }

    [Fact]
    public void Tampered_payload_is_rejected()
    {
        var s = T.Jwt();
        var token = new JwtTokenService(Options.Create(s)).CreateAccessToken(U(true), DateTime.UtcNow, "pwd");
        var parts = token.Split('.');
        var payload = new JwtSecurityTokenHandler().ReadJwtToken(token).Payload;
        payload["role"] = "Administrator";
        var forged = parts[0] + "." + Base64UrlEncoder.Encode(payload.SerializeToJson()) + "." + parts[2];
        Assert.ThrowsAny<SecurityTokenException>(() => Validate(forged, s));
    }

    [Fact]
    public void Unsigned_alg_none_token_is_rejected()
    {
        var s = T.Jwt();
        var unsigned = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            new JwtHeader(), new JwtPayload(s.Issuer, s.Audience, [new Claim("sub", "1"), new Claim(ClaimTypes.Role, "Administrator")], DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(10))));
        Assert.ThrowsAny<SecurityTokenException>(() => Validate(unsigned, s));
    }

    [Fact]
    public void Other_hmac_algorithms_are_rejected()
    {
        var key = Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(64));

        var s = T.Jwt(j => j.Key = key);

        var creds = new SigningCredentials(
            SigningKeys.Create(s.Key),
            SecurityAlgorithms.HmacSha512);

        var token = new JwtSecurityTokenHandler().WriteToken(
            new JwtSecurityToken(
                s.Issuer,
                s.Audience,
                [new Claim("sub", "1")],
                DateTime.UtcNow.AddMinutes(-1),
                DateTime.UtcNow.AddMinutes(5),
                creds));

        Assert.ThrowsAny<SecurityTokenException>(
            () => Validate(token, s));
    }

    [Fact]
    public void Expired_token_is_rejected_and_clock_skew_is_honoured()
    {
        var s = T.Jwt(j => j.ClockSkewSeconds = 0);
        var creds = new SigningCredentials(SigningKeys.Create(s.Key), SecurityAlgorithms.HmacSha256);
        var expired = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(s.Issuer, s.Audience, [new Claim("sub", "1")], DateTime.UtcNow.AddMinutes(-10), DateTime.UtcNow.AddSeconds(-10), creds));

        Assert.Throws<SecurityTokenExpiredException>(() => Validate(expired, s));
        Validate(expired, T.Jwt(j => j.ClockSkewSeconds = 60)); // within the configured skew
    }

    [Fact]
    public void Wrong_issuer_and_audience_are_rejected()
    {
        var token = new JwtTokenService(Options.Create(T.Jwt())).CreateAccessToken(U(true), DateTime.UtcNow, "pwd");
        Assert.ThrowsAny<SecurityTokenException>(() => Validate(token, T.Jwt(j => j.Issuer = "https://evil.test")));
        Assert.ThrowsAny<SecurityTokenException>(() => Validate(token, T.Jwt(j => j.Audience = "https://evil.test")));
    }

    [Fact]
    public void Key_rotation_previous_keys_validate_but_never_sign()
    {
        var oldKey = new string('o', 48);
        var oldToken = new JwtTokenService(Options.Create(T.Jwt(j => j.Key = oldKey))).CreateAccessToken(U(true), DateTime.UtcNow, "pwd");

        var rotated = T.Jwt(j => { j.Key = new string('n', 48); j.PreviousKeys = [oldKey]; });
        Validate(oldToken, rotated); // still accepted during the rotation window

        var newToken = new JwtTokenService(Options.Create(rotated)).CreateAccessToken(U(true), DateTime.UtcNow, "pwd");
        Assert.ThrowsAny<SecurityTokenException>(() => Validate(newToken, T.Jwt(j => j.Key = oldKey))); // signed with the NEW key

        Assert.ThrowsAny<SecurityTokenException>(() => Validate(oldToken, T.Jwt(j => j.Key = new string('n', 48)))); // after PreviousKeys removed
    }

    [Fact]
    public void Tokens_carry_a_key_id_and_unique_jti()
    {
        var svc = new JwtTokenService(Options.Create(T.Jwt()));
        var a = new JwtSecurityTokenHandler().ReadJwtToken(svc.CreateAccessToken(U(true), DateTime.UtcNow, "pwd"));
        var b = new JwtSecurityTokenHandler().ReadJwtToken(svc.CreateAccessToken(U(true), DateTime.UtcNow, "pwd"));
        Assert.False(string.IsNullOrEmpty(a.Header.Kid));
        Assert.NotEqual(a.Id, b.Id);
    }
}
