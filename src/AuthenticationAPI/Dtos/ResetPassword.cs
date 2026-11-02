using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Dtos;

public class ResetPassword
{
    [Required, EmailAddress, StringLength(320)]
    public string Email { get; set; } = string.Empty;

    [Required, StringLength(256)]
    public string Token { get; set; } = string.Empty;

    // Strength is enforced by the configurable password policy in the service (Security:Password).
    [Required, StringLength(1024)]
    public string NewPassword { get; set; } = string.Empty;

    [Required]
    [Compare(nameof(NewPassword), ErrorMessage = "'Password' and 'ConfirmPassword' must match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}
