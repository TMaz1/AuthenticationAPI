using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationAPI.Services.Token;

public interface ITokenService
{
    /// <summary>Issues a signed access token. Claims "IsVerified" reflect the account's real state.</summary>
    string CreateAccessToken(User user, DateTime authTimeUtc, string amr);
}

public static class SigningKeys
{
    public static SymmetricSecurityKey Create(string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        // kid lets validators pick the right key during rotation without trying all of them
        var kid = Convert.ToHexString(SHA256.HashData(bytes))[..16].ToLowerInvariant();
        return new SymmetricSecurityKey(bytes) { KeyId = kid };
    }

    public static IReadOnlyList<SecurityKey> ValidationKeys(JwtSettings s) =>
        new[] { s.Key }.Concat(s.PreviousKeys).Select(k => (SecurityKey)Create(k)).ToList();
}

public static class TokenValidation
{
    /// <summary>The single definition of how access tokens are validated (used by the JWT bearer middleware and by tests).</summary>
    public static TokenValidationParameters Create(JwtSettings jwt) => new()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        RequireExpirationTime = true,
        RequireSignedTokens = true,
        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKeys = SigningKeys.ValidationKeys(jwt),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256], // no algorithm confusion / "none"
        ClockSkew = TimeSpan.FromSeconds(jwt.ClockSkewSeconds)
    };
}

public sealed class JwtTokenService(IOptions<JwtSettings> options) : ITokenService
{
    private readonly JwtSettings _s = options.Value;
    private readonly SigningCredentials _creds = new(SigningKeys.Create(options.Value.Key), SecurityAlgorithms.HmacSha256);

    public string CreateAccessToken(User user, DateTime authTimeUtc, string amr)
    {
        var now = DateTime.UtcNow;
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(ClaimTypes.Role, user.Role.ToString()),
            new("IsVerified", user.IsActive ? "true" : "false"),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("sstamp", user.SecurityStamp),
            new("auth_time", new DateTimeOffset(authTimeUtc, TimeSpan.Zero).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("amr", amr)
        };

        var token = new JwtSecurityToken(
            _s.Issuer,
            _s.Audience,
            claims,
            notBefore: now,
            expires: now.AddMinutes(_s.AccessTokenExpiration),
            signingCredentials: _creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
