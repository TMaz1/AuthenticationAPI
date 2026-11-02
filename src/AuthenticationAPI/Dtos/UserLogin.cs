using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Dtos;

public class UserLogin
{
    [Required(ErrorMessage = "Please fill the '{0}' field"), EmailAddress, StringLength(320)]
    public string Email { get; set; } = string.Empty;
    [Required(ErrorMessage = "Please fill the '{0}' field"), StringLength(1024)]
    public string Password { get; set; } = string.Empty;
    /// <summary>Opt-in persistent session: lengthens the refresh-token lifetime. Does NOT skip MFA.</summary>
    public bool RememberMe { get; set; }
    /// <summary>Credential from a previous "trust this device" MFA success. Only skips the MFA step.</summary>
    [StringLength(128)]
    public string? TrustedDeviceToken { get; set; }
}
