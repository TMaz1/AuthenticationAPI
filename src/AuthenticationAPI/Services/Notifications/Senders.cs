using System.Net;
using System.Net.Mail;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Utils.Logger;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services.Notifications;

public interface IEmailSender
{
    Task SendAsync(string to, string subject, string htmlBody, CancellationToken ct);
}

/// <summary>Provider abstraction for SMS. Implement and register your own vendor integration; no vendor is coupled to business logic.</summary>
public interface ISmsSender
{
    Task SendAsync(string toE164, string message, CancellationToken ct);
}

public sealed class SmtpEmailSender(IOptions<SmtpSettings> options, IOptions<AppSettings> app) : IEmailSender
{
    public async Task SendAsync(string to, string subject, string htmlBody, CancellationToken ct)
    {
        var s = options.Value;
        var from = s.FromEmail ?? throw new InvalidOperationException("SmtpSettings:FromEmail is not configured.");
        using var mail = new MailMessage(from, to)
        {
            Subject = $"[{app.Value.AppName}] {subject}",
            Body = htmlBody,
            IsBodyHtml = true
        };
        using var smtp = new SmtpClient(s.Host)
        {
            Port = s.Port,
            Credentials = new NetworkCredential(s.Username, s.Password),
            EnableSsl = true,
            Timeout = 15_000
        };
        await smtp.SendMailAsync(mail, ct); // failures propagate so the outbox can retry
    }
}

/// <summary>Development-only: records that an email would have been sent, without its content (which holds secrets).</summary>
public sealed class LoggingEmailSender(IAppLogger<LoggingEmailSender> logger) : IEmailSender
{
    public Task SendAsync(string to, string subject, string htmlBody, CancellationToken ct)
    {
        logger.Warn("SMTP not configured: email '{Subject}' to {Recipient} was NOT delivered", subject, Identifiers.EmailId(to));
        return Task.CompletedTask;
    }
}

public sealed class LoggingSmsSender(IAppLogger<LoggingSmsSender> logger) : ISmsSender
{
    public Task SendAsync(string toE164, string message, CancellationToken ct)
    {
        logger.Warn("SMS provider 'Log': message to {Recipient} was NOT delivered", Identifiers.MaskPhone(toE164));
        return Task.CompletedTask;
    }
}

public sealed class NullSmsSender : ISmsSender
{
    public Task SendAsync(string toE164, string message, CancellationToken ct) =>
        throw new InvalidOperationException("No SMS provider is configured.");
}
