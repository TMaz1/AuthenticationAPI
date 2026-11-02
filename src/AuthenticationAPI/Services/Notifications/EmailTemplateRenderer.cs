using System.Net;
using AuthenticationAPI.Dtos;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Notifications;

public sealed record RenderedEmail(string Subject, string Html);

public interface IEmailTemplateRenderer
{
    RenderedEmail Render(string notificationType, NotificationPayload payload);
}

public sealed class EmailTemplateRenderer(IOptions<AppSettings> app) : IEmailTemplateRenderer
{
    // resolved against the application base directory, not the process working directory
    private static readonly string Root = Path.Combine(AppContext.BaseDirectory, "EmailTemplates");

    public RenderedEmail Render(string type, NotificationPayload p)
    {
        var (file, subject) = type switch
        {
            NotificationTypes.Verification => ("verify-account.html", "Verify Your Account"),
            NotificationTypes.PasswordReset => ("password-reset.html", "Reset Your Password"),
            NotificationTypes.MfaCode => ("mfa-code.html", "Your One-Time MFA Code"),
            NotificationTypes.PasswordChanged => ("password-changed.html", "Your password was changed"),
            NotificationTypes.MfaDisabled => ("mfa-disabled.html", "Two-factor authentication was turned off"),
            _ => throw new InvalidOperationException($"Unknown email notification type '{type}'.")
        };

        var appName = WebUtility.HtmlEncode(app.Value.AppName);
        var footerPath = Path.Combine(Root, "footer.html");
        var footer = File.Exists(footerPath) ? File.ReadAllText(footerPath) : $"<p>&copy; {DateTime.UtcNow.Year} {appName}. All rights reserved.</p>";

        var html = File.ReadAllText(Path.Combine(Root, file))
            .Replace("{{EMAIL_FOOTER}}", footer)
            .Replace("{{CURRENT_YEAR}}", DateTime.UtcNow.Year.ToString())
            .Replace("{{APP_NAME}}", appName)
            .Replace("{{LINK}}", WebUtility.HtmlEncode(p.Link ?? string.Empty))
            .Replace("{{OTP}}", WebUtility.HtmlEncode(p.Code ?? string.Empty))
            .Replace("{{EXPIRY_HOURS}}", p.Expiry.ToString())
            .Replace("{{EXPIRY_MINUTES}}", p.Expiry.ToString());

        return new RenderedEmail(subject, html);
    }
}
