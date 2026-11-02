using CorrelationId.Abstractions;
using Serilog;

namespace AuthenticationAPI.Utils.Logger;

public class AppLogger<T>(ICorrelationContextAccessor correlation) : IAppLogger<T>
{
    private readonly Serilog.ILogger _logger = Log.ForContext<T>();
    private readonly ICorrelationContextAccessor _correlation = correlation;

    private string CorrelationId => _correlation?.CorrelationContext?.CorrelationId ?? "none";

    public void Info(string messageTemplate, params object[] propertyValues)
    {
        _logger.ForContext(nameof(CorrelationId), CorrelationId).Information(messageTemplate, propertyValues);
    }

    public void Warn(string messageTemplate, params object[] propertyValues)
    {
        _logger.ForContext(nameof(CorrelationId), CorrelationId).Warning(messageTemplate, propertyValues);
    }

    public void Error(Exception ex, string messageTemplate, params object[] propertyValues)
    {
        _logger.ForContext(nameof(CorrelationId), CorrelationId).Error(ex, messageTemplate, propertyValues);
    }

    public void Debug(string messageTemplate, params object[] propertyValues)
    {
        _logger.ForContext(nameof(CorrelationId), CorrelationId).Debug(messageTemplate, propertyValues);
    }
}
