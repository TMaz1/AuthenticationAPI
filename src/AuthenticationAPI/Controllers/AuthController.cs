using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationAPI.Data;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models.Enums;
using AuthenticationAPI.Services.Authentication;
using AuthenticationAPI.Services.Mfa;
using AuthenticationAPI.Services.Notifications;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Utils.Logger;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
[RequestSizeLimit(16 * 1024)]
public class AuthController(
    IAuthService authService,
    IMfaService mfaService,
    IWebHostEnvironment env,
    INotificationOutbox outbox,
    AuthDataContext db,
    IAppLogger<AuthController> logger) : ControllerBase
{
    private string Ip => ClientContext.GetIp(HttpContext);

    // ---- registration / login ----------------------------------------------------------------------------

    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<ActionResult<ServiceResponse<bool>>> Register([FromBody] UserRegister request, CancellationToken ct) =>
        Map(await authService.Register(request, Ip, ct));

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<ActionResult<ServiceResponse<AuthResponse>>> Login([FromBody] UserLogin request, CancellationToken ct) =>
        Map(await authService.Login(request, Ip, ct));

    [Authorize]
    [HttpGet("user")]
    public async Task<ActionResult<ServiceResponse<AuthResponse>>> GetUserData(CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await authService.GetUserData(id, ct)) : InvalidClaims<AuthResponse>();

    // ---- verification -------------------------------------------------------------------------------------

    [AllowAnonymous]
    [HttpPost("verify-account")]
    public async Task<ActionResult<ServiceResponse<bool>>> VerifyAccount([FromBody] TokenRequest request, CancellationToken ct) =>
        Map(await authService.VerifyAccount(request.Token, Ip, ct));

    [Authorize]
    [HttpPost("resend-verification")]
    public async Task<ActionResult<ServiceResponse<bool>>> ResendVerificationEmail(CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await authService.ResendVerificationEmail(id, ct)) : InvalidClaims<bool>();

    // ---- sessions -----------------------------------------------------------------------------------------

    /// <summary>
    /// The refresh token is itself the credential, so no access token is required (an expired access token is the
    /// normal reason to call this). Previously this required a valid access token, which defeated its purpose.
    /// </summary>
    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public async Task<ActionResult<ServiceResponse<AuthResponse>>> RefreshToken([FromBody] TokenRequest request, CancellationToken ct) =>
        Map(await authService.RefreshToken(request.Token, Ip, ct));

    [Authorize]
    [HttpPost("logout")]
    public async Task<ActionResult<ServiceResponse<bool>>> Logout(CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await authService.Logout(id, ct)) : InvalidClaims<bool>();

    [Authorize(Policy = "VerifiedUser")]
    [HttpPost("sessions/revoke-all")]
    public async Task<ActionResult<ServiceResponse<bool>>> RevokeAllSessions(CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await authService.RevokeAllSessions(id, ct)) : InvalidClaims<bool>();

    // ---- password recovery --------------------------------------------------------------------------------

    [AllowAnonymous]
    [HttpPost("password-reset-request")]
    public async Task<ActionResult<ServiceResponse<bool>>> RequestPasswordReset([FromBody] UserEmailRequest request, CancellationToken ct) =>
        Map(await authService.RequestPasswordReset(request.Email, Ip, ct));

    [AllowAnonymous]
    [HttpPost("reset-password")]
    public async Task<ActionResult<ServiceResponse<bool>>> ResetPassword([FromBody] ResetPassword request, CancellationToken ct) =>
        Map(await authService.ResetPassword(request, Ip, ct));

    // ---- administration -----------------------------------------------------------------------------------

    [Authorize(Policy = "AdminVerified")]
    [HttpPost("admin/unlock")]
    public async Task<ActionResult<ServiceResponse<bool>>> UnlockUser([FromBody] UserEmailRequest request, CancellationToken ct) =>
        TryGetUserId(out var actor) ? Map(await authService.UnlockUser(request.Email, actor, ct)) : InvalidClaims<bool>();

    [Authorize(Policy = "AdminRecentAuth")]
    [HttpPost("admin/disable")]
    public async Task<ActionResult<ServiceResponse<bool>>> DisableUser([FromBody] UserEmailRequest request, CancellationToken ct) =>
        TryGetUserId(out var actor) ? Map(await authService.SetUserDisabled(request.Email, true, actor, ct)) : InvalidClaims<bool>();

    [Authorize(Policy = "AdminRecentAuth")]
    [HttpPost("admin/enable")]
    public async Task<ActionResult<ServiceResponse<bool>>> EnableUser([FromBody] UserEmailRequest request, CancellationToken ct) =>
        TryGetUserId(out var actor) ? Map(await authService.SetUserDisabled(request.Email, false, actor, ct)) : InvalidClaims<bool>();

    [Authorize(Policy = "AdminRecentAuth")]
    [HttpPost("admin/role")]
    public async Task<ActionResult<ServiceResponse<bool>>> SetRole([FromBody] SetRoleRequest request, CancellationToken ct) =>
        TryGetUserId(out var actor) ? Map(await authService.SetRole(request.Email, request.Role!.Value, actor, ct)) : InvalidClaims<bool>();

    // ---- MFA ----------------------------------------------------------------------------------------------

    [Authorize(Policy = "VerifiedUser")]
    [HttpGet("mfa/setup")]
    public async Task<ActionResult<ServiceResponse<string>>> GenerateMfaSetup([FromQuery] bool forceMfaRegenerate = false, CancellationToken ct = default) =>
        TryGetUserId(out var id) ? Map(await mfaService.SetupMfa(id, forceMfaRegenerate, ct)) : InvalidClaims<string>();

    [Authorize(Policy = "VerifiedUser")]
    [HttpPost("mfa/enable")]
    public async Task<ActionResult<ServiceResponse<bool>>> EnableMfa([FromBody] OtpRequest request, CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await mfaService.EnableMfa(id, request, ct)) : InvalidClaims<bool>();

    [AllowAnonymous]
    [HttpPost("mfa/verify")]
    public async Task<ActionResult<ServiceResponse<AuthResponse>>> VerifyMfa([FromBody] MfaVerifyRequest request, CancellationToken ct) =>
        Map(await mfaService.VerifyMfa(request, Ip, ct));

    [Authorize(Policy = "VerifiedUser")]
    [HttpPost("mfa/disable")]
    public async Task<ActionResult<ServiceResponse<bool>>> DisableMfa([FromBody] DisableMfaRequest request, CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await mfaService.DisableMfa(id, request, ct)) : InvalidClaims<bool>();

    [Authorize(Policy = "AdminRecentAuth")]
    [HttpPost("mfa/admin/reset")]
    public async Task<ActionResult<ServiceResponse<bool>>> ResetMfa([FromBody] UserEmailRequest request, CancellationToken ct) =>
        TryGetUserId(out var actor) ? Map(await mfaService.ResetMfaAdmin(request.Email, actor, ct)) : InvalidClaims<bool>();

    /// <summary>Requires the challenge token from the login response; no longer usable to spam arbitrary addresses.</summary>
    [AllowAnonymous]
    [HttpPost("send-email-otp")]
    public async Task<ActionResult<ServiceResponse<bool>>> SendEmailOtp([FromBody] MfaSendOtpRequest request, CancellationToken ct) =>
        Map(await mfaService.SendOtp(request, MfaMethodType.Email, Ip, ct));

    [AllowAnonymous]
    [HttpPost("mfa/send-sms-otp")]
    public async Task<ActionResult<ServiceResponse<bool>>> SendSmsOtp([FromBody] MfaSendOtpRequest request, CancellationToken ct) =>
        Map(await mfaService.SendOtp(request, MfaMethodType.Sms, Ip, ct));

    [Authorize(Policy = "VerifiedUser")]
    [HttpPost("mfa/sms/enroll")]
    public async Task<ActionResult<ServiceResponse<bool>>> EnrollPhone([FromBody] SmsEnrollRequest request, CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await mfaService.EnrollPhone(id, request, ct)) : InvalidClaims<bool>();

    [Authorize(Policy = "VerifiedUser")]
    [HttpPost("mfa/sms/confirm")]
    public async Task<ActionResult<ServiceResponse<bool>>> ConfirmPhone([FromBody] CodeRequest request, CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await mfaService.ConfirmPhone(id, request.Code, ct)) : InvalidClaims<bool>();

    // ---- trusted devices ----------------------------------------------------------------------------------

    [Authorize(Policy = "VerifiedUser")]
    [HttpGet("devices")]
    public async Task<ActionResult<ServiceResponse<List<TrustedDeviceInfo>>>> ListDevices(CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await mfaService.ListDevices(id, ct)) : InvalidClaims<List<TrustedDeviceInfo>>();

    [Authorize(Policy = "VerifiedUser")]
    [HttpDelete("devices/{deviceId:guid}")]
    public async Task<ActionResult<ServiceResponse<bool>>> RevokeDevice(Guid deviceId, CancellationToken ct) =>
        TryGetUserId(out var id) ? Map(await mfaService.RevokeDevice(id, deviceId, ct)) : InvalidClaims<bool>();

    // ---- development helpers ------------------------------------------------------------------------------

    /// <summary>Queues sample emails. Development environment only and administrators only (was anonymous in every environment).</summary>
    [Authorize(Policy = "AdminVerified")]
    [HttpPost("email/test/all")]
    public async Task<IActionResult> SendAllTestEmails([FromQuery, System.ComponentModel.DataAnnotations.EmailAddress] string to, CancellationToken ct)
    {
        if (!env.IsDevelopment()) return NotFound();
        if (string.IsNullOrWhiteSpace(to)) return BadRequest(new { Message = "Email address is required." });

        outbox.Enqueue(NotificationTypes.MfaCode, new NotificationPayload(to, null, "123456", 5));
        outbox.Enqueue(NotificationTypes.Verification, new NotificationPayload(to, "https://example.com/verify?token=abc123", null, 1));
        outbox.Enqueue(NotificationTypes.PasswordReset, new NotificationPayload(to, "https://example.com/reset?token=xyz789", null, 30));
        await db.SaveChangesAsync(ct);
        logger.Info("Queued sample emails");
        return Ok(new { Message = "Sample emails queued." });
    }

    [Authorize(Policy = "VerifiedUser")]
    [HttpGet("protected-resource")]
    public IActionResult ProtectedResource() => Ok("You are verified!");

    // ---- helpers ------------------------------------------------------------------------------------------

    private bool TryGetUserId(out int userId)
    {
        var sub = User.FindFirstValue(JwtRegisteredClaimNames.Sub) ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (int.TryParse(sub, out userId)) return true;
        logger.Warn("Invalid or missing user id claim");
        return false; // fail closed
    }

    private ActionResult<ServiceResponse<T>> InvalidClaims<T>() =>
        Map(ServiceResponse<T>.Fail(ResultKind.Unauthorized, "Invalid or missing user ID in token."));

    private ActionResult<ServiceResponse<T>> Map<T>(ServiceResponse<T> response)
    {
        if (response.Success) return Ok(response);
        if (response.RetryAfterSeconds is int seconds) Response.Headers.RetryAfter = seconds.ToString();

        var status = response.Kind switch
        {
            ResultKind.TooManyRequests => StatusCodes.Status429TooManyRequests,
            ResultKind.NotFound => StatusCodes.Status404NotFound,
            ResultKind.Forbidden => StatusCodes.Status403Forbidden,
            ResultKind.Unauthorized => StatusCodes.Status401Unauthorized,
            ResultKind.ServerError => StatusCodes.Status500InternalServerError,
            _ => StatusCodes.Status400BadRequest
        };
        return new ObjectResult(response) { StatusCode = status };
    }
}
