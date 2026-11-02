using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using AuthenticationAPI.Models.Enums;

namespace AuthenticationAPI.Dtos;

public class UserRegister
{
    [StringLength(100)]
    public string? Username { get; set; }

    [Required(ErrorMessage = "Please fill the '{0}' field"), EmailAddress, StringLength(320)]
    public string Email { get; set; } = string.Empty;

    // Strength is enforced by the configurable password policy in AuthService (Security:Password).
    [Required(ErrorMessage = "Please fill the '{0}' field"), StringLength(1024)]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please fill the 'Confirm Password' field"), Compare("Password", ErrorMessage = "'Password' and 'Confirm Password' do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please fill the 'First Name' field"), MinLength(3, ErrorMessage = "{0} must be at least 3 characters"), StringLength(100)]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please fill the '{0}' field"), MinLength(3, ErrorMessage = "{0} must be at least 3 characters"), StringLength(100)]
    public string LastName { get; set; } = string.Empty;

    [Phone(ErrorMessage = "Invalid phone number format."), StringLength(32)]
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Accepted for backward compatibility but IGNORED: self-registration always yields the Viewer role.
    /// Roles are changed only by an administrator via POST api/auth/admin/role.
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public RoleType Role { get; set; } = RoleType.Viewer;
}
