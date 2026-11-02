using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models.Enums;

namespace AuthenticationAPI.Services.Authentication;

public interface IAuthService
{
    Task<ServiceResponse<bool>> Register(UserRegister request, string ip, CancellationToken ct = default);
    Task<ServiceResponse<AuthResponse>> Login(UserLogin request, string ip, CancellationToken ct = default);
    Task<ServiceResponse<AuthResponse>> GetUserData(int userId, CancellationToken ct = default);
    Task<ServiceResponse<bool>> VerifyAccount(string token, string ip, CancellationToken ct = default);
    Task<ServiceResponse<bool>> ResendVerificationEmail(int userId, CancellationToken ct = default);
    Task<ServiceResponse<AuthResponse>> RefreshToken(string refreshToken, string ip, CancellationToken ct = default);
    Task<ServiceResponse<bool>> Logout(int userId, CancellationToken ct = default);
    Task<ServiceResponse<bool>> RevokeAllSessions(int userId, CancellationToken ct = default);
    Task<ServiceResponse<bool>> RequestPasswordReset(string email, string ip, CancellationToken ct = default);
    Task<ServiceResponse<bool>> ResetPassword(ResetPassword request, string ip, CancellationToken ct = default);
    Task<ServiceResponse<bool>> UnlockUser(string email, int actorUserId, CancellationToken ct = default);
    Task<ServiceResponse<bool>> SetUserDisabled(string email, bool disabled, int actorUserId, CancellationToken ct = default);
    Task<ServiceResponse<bool>> SetRole(string email, RoleType role, int actorUserId, CancellationToken ct = default);
}
