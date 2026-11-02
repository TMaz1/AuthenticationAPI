using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Dtos;

public class TokenRequest
{
    [Required(ErrorMessage = "Please fill the '{0}' field"), StringLength(256)]
    public string Token { get; set; } = string.Empty;
}
