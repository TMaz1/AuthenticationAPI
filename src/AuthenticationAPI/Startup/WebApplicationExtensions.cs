using CorrelationId;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Serilog;

namespace AuthenticationAPI.Startup;

public static class WebApplicationExtensions
{
    public static WebApplication UseAuthApi(this WebApplication app)
    {
        var config = app.Configuration;

        if (config.GetValue<bool>("Security:ForwardedHeaders:Enabled")) app.UseForwardedHeaders();

        app.UseCorrelationId();
        app.UseSerilogRequestLogging(options =>
        {
            options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms (CorrelationId: {CorrelationId})";
            options.GetLevel = (ctx, _, ex) => ex is not null || ctx.Response.StatusCode >= 500
                ? Serilog.Events.LogEventLevel.Error
                : ctx.Request.Path.StartsWithSegments("/health") ? Serilog.Events.LogEventLevel.Debug : Serilog.Events.LogEventLevel.Information;
        });

        // unhandled exceptions -> RFC 9457 problem details without stack traces or exception messages
        app.UseExceptionHandler();
        app.UseStatusCodePages();

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        else
        {
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        if (config.GetSection("Security:Cors:AllowedOrigins").Get<string[]>() is { Length: > 0 }) app.UseCors();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();
        // liveness: process is up. readiness: dependencies. Both return only the status word (no infrastructure detail).
        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
        app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains("ready") });
        return app;
    }
}
