using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Dtos;

public class UserEmailRequest
{
    [Required(ErrorMessage = "Please fill the '{0}' field"), EmailAddress, StringLength(320)]
    public string Email { get; set; } = string.Empty;
}

public class SetRoleRequest
{
    [Required, EmailAddress, StringLength(320)]
    public string Email { get; set; } = string.Empty;
    [Required]
    public Models.Enums.RoleType? Role { get; set; }
}

public class TrustedDeviceInfo
{
    public Guid Id { get; set; }
    public string? Label { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}
