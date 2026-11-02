namespace AuthenticationAPI.Dtos;

/// <summary>Bound from the existing "AppSettings" section for backward compatibility.</summary>
public class JwtSettings
{
    public string Key { get; set; } = string.Empty;
    /// <summary>Previously used signing keys that are still accepted for validation (key rotation). Never used for signing.</summary>
    public string[] PreviousKeys { get; set; } = [];
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int AccessTokenExpiration { get; set; } = 15; // minutes
    public int RefreshTokenExpiration { get; set; } = 7; // days
    public int RememberMeRefreshTokenExpiration { get; set; } = 30; // days
    public int PasswordResetTokenExpiration { get; set; } = 30; // minutes
    public int VerificationTokenExpiration { get; set; } = 24; // hours
    /// <summary>Tolerated clock difference between token issuer and validator, in seconds.</summary>
    public int ClockSkewSeconds { get; set; } = 30;
}
