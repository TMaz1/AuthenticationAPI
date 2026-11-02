namespace AuthenticationAPI.Dtos;

public class AuthResponse
{
    public UserResponse? User { get; set; }
    public string? Token { get; set; }
    public string? RefreshToken { get; set; }
    public MfaInfo? Mfa { get; set; }
    /// <summary>Present only when a trusted device was just created or rotated.</summary>
    public string? TrustedDeviceToken { get; set; }
}
