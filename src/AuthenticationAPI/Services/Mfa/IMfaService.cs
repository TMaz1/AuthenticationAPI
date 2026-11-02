using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models.Enums;

namespace AuthenticationAPI.Services.Mfa;

public interface IMfaService
{
    Task<ServiceResponse<string>> SetupMfa(int userId, bool forceMfaRegenerate, CancellationToken ct = default);
    Task<ServiceResponse<bool>> EnableMfa(int userId, OtpRequest request, CancellationToken ct = default);
    Task<ServiceResponse<AuthResponse>> VerifyMfa(MfaVerifyRequest request, string ip, CancellationToken ct = default);
    Task<ServiceResponse<bool>> DisableMfa(int userId, DisableMfaRequest request, CancellationToken ct = default);
    Task<ServiceResponse<bool>> ResetMfaAdmin(string email, int actorUserId, CancellationToken ct = default);
    Task<ServiceResponse<bool>> SendOtp(MfaSendOtpRequest request, MfaMethodType method, string ip, CancellationToken ct = default);
    Task<ServiceResponse<bool>> EnrollPhone(int userId, SmsEnrollRequest request, CancellationToken ct = default);
    Task<ServiceResponse<bool>> ConfirmPhone(int userId, string code, CancellationToken ct = default);
    Task<ServiceResponse<List<TrustedDeviceInfo>>> ListDevices(int userId, CancellationToken ct = default);
    Task<ServiceResponse<bool>> RevokeDevice(int userId, Guid deviceId, CancellationToken ct = default);
}
