using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Dtos;

/// <summary>Enable MFA: a current authenticator code plus the account password (re-authentication).</summary>
public class OtpRequest
{
    [Required, StringLength(8, MinimumLength = 6)]
    public string OtpCode { get; set; } = string.Empty;
    [Required, StringLength(1024)]
    public string Password { get; set; } = string.Empty;
}

/// <summary>Disable MFA: password plus a current authenticator code.</summary>
public class DisableMfaRequest
{
    [Required, StringLength(1024)]
    public string Password { get; set; } = string.Empty;
    [Required, StringLength(8, MinimumLength = 6)]
    public string OtpCode { get; set; } = string.Empty;
}

public class SmsEnrollRequest
{
    /// <summary>E.164 format, e.g. +14155550123.</summary>
    [Required, StringLength(16)]
    public string PhoneNumber { get; set; } = string.Empty;
    [Required, StringLength(1024)]
    public string Password { get; set; } = string.Empty;
    /// <summary>Required when MFA is already enabled.</summary>
    [StringLength(8)]
    public string? OtpCode { get; set; }
}

public class CodeRequest
{
    [Required, StringLength(8, MinimumLength = 6)]
    public string Code { get; set; } = string.Empty;
}
