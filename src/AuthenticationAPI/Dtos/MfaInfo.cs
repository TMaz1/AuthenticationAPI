using AuthenticationAPI.Models.Enums;

namespace AuthenticationAPI.Dtos;

public class MfaInfo
{
    public bool RequiresMfa { get; set; }
    public MfaMethodType? SelectedMethod { get; set; }
    public List<MfaMethodType> AvailableMethods { get; set; } = [MfaMethodType.Totp, MfaMethodType.Email];
    /// <summary>Opaque single-use token proving the password step succeeded. Must accompany every MFA verify/send-otp call.</summary>
    public string? ChallengeToken { get; set; }
}
