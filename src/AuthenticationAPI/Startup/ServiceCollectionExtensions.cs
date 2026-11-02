using System.IdentityModel.Tokens.Jwt;
using System.Net;
using AuthenticationAPI.Configuration;
using AuthenticationAPI.Data;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models.Enums;
using AuthenticationAPI.Services.Authentication;
using AuthenticationAPI.Services.Mfa;
using AuthenticationAPI.Services.Notifications;
using AuthenticationAPI.Services.Password;
using AuthenticationAPI.Services.Security;
using AuthenticationAPI.Services.Token;
using AuthenticationAPI.Utils.Logger;
using CorrelationId.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using StackExchange.Redis;

namespace AuthenticationAPI.Startup;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAuthApi(this IServiceCollection services, IConfiguration config, IHostEnvironment env)
    {
        AddOptions(services, config, env);
        AddPersistence(services, config);
        AddRedis(services, config);
        AddAuthentication(services);
        AddApplicationServices(services, config, env);

        services.AddDefaultCorrelationId(options =>
        {
            options.AddToLoggingScope = true;
            options.RequestHeader = "X-Correlation-ID";
            options.ResponseHeader = "X-Correlation-ID";
            options.UpdateTraceIdentifier = true;
        });
        return services;
    }

    private static void AddOptions(IServiceCollection services, IConfiguration config, IHostEnvironment env)
    {
        // "AppSettings" keeps its historical name; it holds JWT settings plus AppName/AppLink.
        services.AddOptions<JwtSettings>().Bind(config.GetSection("AppSettings")).ValidateOnStart();
        services.AddOptions<AppSettings>().Bind(config.GetSection("AppSettings"))
            .Validate(a => !env.IsProduction() || a.AppLink.StartsWith("https://", StringComparison.OrdinalIgnoreCase), "AppSettings:AppLink must be an https URL in Production.")
            .ValidateOnStart();
        services.AddOptions<SecurityOptions>().Bind(config.GetSection(SecurityOptions.SectionName)).ValidateOnStart();
        services.AddOptions<SmtpSettings>().Bind(config.GetSection("SmtpSettings"))
            .Validate(s => !env.IsProduction() || SmtpConfigured(s), "SmtpSettings must be configured in Production.")
            .ValidateOnStart();

        services.AddSingleton<IValidateOptions<JwtSettings>, JwtSettingsValidator>();
        services.AddSingleton<IValidateOptions<SecurityOptions>, SecurityOptionsValidator>();
    }

    public static bool SmtpConfigured(SmtpSettings s) =>
        !string.IsNullOrWhiteSpace(s.Host) && !s.Host.StartsWith('<') && !string.IsNullOrWhiteSpace(s.FromEmail) && !s.FromEmail.StartsWith('<');

    private static void AddPersistence(IServiceCollection services, IConfiguration config)
    {
        // No automatic migration at startup: schema changes are applied deliberately (see docs/OPERATIONS.md).
        services.AddDbContext<AuthDataContext>(o => o.UseSqlServer(config.GetConnectionString("DefaultConnection")));
    }

    private static void AddRedis(IServiceCollection services, IConfiguration config)
    {
        services.AddSingleton<IConnectionMultiplexer>(sp =>
        {
            var redis = sp.GetRequiredService<IOptions<SecurityOptions>>().Value.Redis;
            var cs = config.GetConnectionString("Redis");
            var options = ConfigurationOptions.Parse(string.IsNullOrWhiteSpace(cs) || cs.StartsWith('<') ? "localhost:6379" : cs);
            options.AbortOnConnectFail = false; // start even if Redis is down; ResilientRateLimitStore degrades safely
            options.ConnectTimeout = redis.ConnectTimeoutMs;
            options.SyncTimeout = redis.OperationTimeoutMs;
            options.AsyncTimeout = redis.OperationTimeoutMs;
            return ConnectionMultiplexer.Connect(options);
        });
        services.AddSingleton<RedisRateLimitStore>();
        services.AddSingleton(new InMemoryRateLimitStore());
        services.AddSingleton<IRateLimitStore, ResilientRateLimitStore>();
    }

    private static void AddAuthentication(IServiceCollection services)
    {
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        services.AddMemoryCache();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<JwtSettings>, IServiceProvider>((options, jwtOptions, sp) =>
            {
                var jwt = jwtOptions.Value;
                options.MapInboundClaims = false;
                options.TokenValidationParameters = TokenValidation.Create(jwt);

                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async ctx =>
                    {
                        var principal = ctx.Principal;
                        var ok = int.TryParse(principal?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value, out var userId);
                        var validator = ctx.HttpContext.RequestServices.GetRequiredService<ISessionValidator>();
                        if (!ok || !await validator.IsValidAsync(userId, principal?.FindFirst("sstamp")?.Value, ctx.HttpContext.RequestAborted))
                            ctx.Fail("Session is no longer valid.");
                    },
                    OnAuthenticationFailed = ctx =>
                    {
                        // type only: exception messages for bad tokens can echo token fragments
                        Serilog.Log.Warning("JWT rejected ({Reason})", ctx.Exception.GetType().Name);
                        return Task.CompletedTask;
                    }
                };
            });

        services.AddAuthorizationBuilder()
            .AddPolicy("VerifiedUser", p => p.RequireClaim("IsVerified", "true"))
            .AddPolicy("AdminVerified", p => p.RequireRole(nameof(RoleType.Administrator)).RequireClaim("IsVerified", "true"))
            .AddPolicy("AdminRecentAuth", p => p
                .RequireRole(nameof(RoleType.Administrator))
                .RequireClaim("IsVerified", "true")
                .AddRequirements(new RecentAuthenticationRequirement()));

        services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, RecentAuthenticationHandler>();
    }

    private static void AddApplicationServices(IServiceCollection services, IConfiguration config, IHostEnvironment env)
    {
        services.AddSingleton<ISecretProtector>(sp =>
            new AesGcmSecretProtector(sp.GetRequiredService<IOptions<SecurityOptions>>().Value.EncryptionKey));
        services.AddSingleton<ISessionValidator, SessionValidator>();
        services.AddSingleton(TimeProvider.System);

        services.AddScoped<IPasswordService, PasswordService>();
        services.AddScoped<ITokenService, JwtTokenService>();
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();
        services.AddScoped<ISessionService, SessionService>();
        services.AddScoped<ISecurityAudit, SecurityAudit>();
        services.AddScoped<ILoginThrottle, LoginThrottle>();
        services.AddScoped<IAbuseGuard, AbuseGuard>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IMfaService, MfaService>();
        services.AddScoped<ITrustedDeviceService, TrustedDeviceService>();
        services.AddScoped<INotificationOutbox, NotificationOutbox>();
        // singleton: it is injected into singletons (stores, workers); it only reads the singleton correlation accessor
        services.AddSingleton(typeof(IAppLogger<>), typeof(AppLogger<>));

        // delivery providers (TryAdd so tests and deployments can substitute their own)
        services.AddSingleton<IEmailTemplateRenderer, EmailTemplateRenderer>();
        var smtp = config.GetSection("SmtpSettings").Get<SmtpSettings>() ?? new SmtpSettings();
        if (SmtpConfigured(smtp)) services.AddSingleton<IEmailSender, SmtpEmailSender>();
        else services.AddSingleton<IEmailSender, LoggingEmailSender>();

        var smsProvider = config.GetSection("Security:Sms:Provider").Value ?? "None";
        if (string.Equals(smsProvider, "Log", StringComparison.OrdinalIgnoreCase)) services.AddSingleton<ISmsSender, LoggingSmsSender>();
        else if (string.Equals(smsProvider, "None", StringComparison.OrdinalIgnoreCase)) services.AddSingleton<ISmsSender, NullSmsSender>();
        // any other value: the deployment registers its own ISmsSender

        services.AddSingleton<OutboxProcessor>();
        services.AddHostedService(sp => sp.GetRequiredService<OutboxProcessor>());
        services.AddSingleton<MaintenanceWorker>();
        services.AddHostedService(sp => sp.GetRequiredService<MaintenanceWorker>());

        services.AddProblemDetails(o => o.CustomizeProblemDetails = ctx =>
            ctx.ProblemDetails.Extensions["correlationId"] = ctx.HttpContext.TraceIdentifier);

        services.AddHealthChecks()
            .AddCheck<SqlHealthCheck>("sql", tags: ["ready"])
            .AddCheck<RedisHealthCheck>("redis", tags: ["ready"]);

        var cors = config.GetSection("Security:Cors:AllowedOrigins").Get<string[]>() ?? [];
        if (cors.Length > 0)
            services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins(cors).WithMethods("GET", "POST", "DELETE").WithHeaders("Authorization", "Content-Type", "X-Correlation-ID")));

        var proxies = config.GetSection("Security:ForwardedHeaders:KnownProxies").Get<string[]>() ?? [];
        if (config.GetValue<bool>("Security:ForwardedHeaders:Enabled"))
        {
            services.Configure<ForwardedHeadersOptions>(o =>
            {
                o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                o.ForwardLimit = 1;
                o.KnownNetworks.Clear();
                o.KnownProxies.Clear();
                foreach (var p in proxies) o.KnownProxies.Add(IPAddress.Parse(p));
            });
        }

        if (env.IsDevelopment())
        {
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Authentication API", Version = "v1" });
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please enter token with Bearer prefix",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    { new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" } }, Array.Empty<string>() }
                });
            });
        }
    }
}

public sealed class RecentAuthenticationRequirement : Microsoft.AspNetCore.Authorization.IAuthorizationRequirement;

public sealed class RecentAuthenticationHandler(IOptions<SecurityOptions> options, TimeProvider time)
    : Microsoft.AspNetCore.Authorization.AuthorizationHandler<RecentAuthenticationRequirement>
{
    protected override Task HandleRequirementAsync(Microsoft.AspNetCore.Authorization.AuthorizationHandlerContext context, RecentAuthenticationRequirement requirement)
    {
        var claim = context.User.FindFirst("auth_time")?.Value;
        if (long.TryParse(claim, out var seconds))
        {
            var age = time.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(seconds);
            if (age >= TimeSpan.Zero - TimeSpan.FromMinutes(1) && age <= TimeSpan.FromMinutes(options.Value.AdminRecentAuthMinutes))
                context.Succeed(requirement);
        }
        return Task.CompletedTask; // no claim / too old => not succeeded => 403 (fail closed)
    }
}

public sealed class SqlHealthCheck(AuthDataContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default) =>
        await db.Database.CanConnectAsync(ct) ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy();
}

/// <summary>Redis down is Degraded, not Unhealthy: rate limiting continues from in-memory fallback counters.</summary>
public sealed class RedisHealthCheck(IConnectionMultiplexer redis) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            await redis.GetDatabase().PingAsync();
            return HealthCheckResult.Healthy();
        }
        catch (Exception)
        {
            return HealthCheckResult.Degraded();
        }
    }
}
