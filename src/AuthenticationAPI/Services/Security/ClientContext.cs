namespace AuthenticationAPI.Services.Security;

public static class ClientContext
{
    /// <summary>Remote address after ForwardedHeaders processing (only trusted when KnownProxies is configured).</summary>
    public static string GetIp(HttpContext http) => http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
