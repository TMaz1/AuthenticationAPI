using System.ComponentModel.DataAnnotations;
using AuthenticationAPI.Models.Enums;

namespace AuthenticationAPI.Dtos;

public class MfaVerifyRequest
{
    [Required, EmailAddress, StringLength(320)]
    public string Email { get; set; } = string.Empty;
    [Required, StringLength(8, MinimumLength = 6)]
    public string Otp { get; set; } = string.Empty;
    public MfaMethodType Method { get; set; } = MfaMethodType.Totp;
    /// <summary>From the login response (Mfa.ChallengeToken).</summary>
    [Required, StringLength(128)]
    public string ChallengeToken { get; set; } = string.Empty;
    /// <summary>Request a trusted-device credential (requires Security:TrustedDevices:Enabled; never granted to administrators).</summary>
    public bool TrustThisDevice { get; set; }
    [StringLength(64)]
    public string? DeviceLabel { get; set; }
}

public class MfaSendOtpRequest
{
    [Required, EmailAddress, StringLength(320)]
    public string Email { get; set; } = string.Empty;
    [Required, StringLength(128)]
    public string ChallengeToken { get; set; } = string.Empty;
}
