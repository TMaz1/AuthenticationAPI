using AuthenticationAPI.Startup;
using Serilog;
using Serilog.Debugging;
using Serilog.Exceptions;

var builder = WebApplication.CreateBuilder(args);

// Serilog sinks/levels are configured in serilog.json
builder.Configuration.AddJsonFile("serilog.json", optional: false, reloadOnChange: true);
SelfLog.Enable(msg => File.AppendAllText("serilog-internal.log", msg));

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithExceptionDetails()
    .Enrich.WithProperty("Application", "AuthenticationAPI")
    .Enrich.WithCorrelationId()
    .CreateLogger();
builder.Host.UseSerilog();

builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    k.Limits.MaxRequestBodySize = 64 * 1024;
});

builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter(System.Text.Json.JsonNamingPolicy.CamelCase, allowIntegerValues: false));
});
builder.Services.AddAuthApi(builder.Configuration, builder.Environment);

var app = builder.Build();
app.UseAuthApi();
app.Run();

public partial class Program;
