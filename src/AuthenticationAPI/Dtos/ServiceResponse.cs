using System.Text.Json.Serialization;

namespace AuthenticationAPI.Dtos;

public enum ResultKind
{
    Ok = 0,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    TooManyRequests,
    ServerError
}

/// <summary>Expected, user-facing failure. The message is safe to return to the client.</summary>
public class AuthException(ResultKind kind, string message) : Exception(message)
{
    public ResultKind Kind { get; } = kind;
    public int? RetryAfterSeconds { get; init; }
}

public class ServiceResponse<T>
{
    public T? Data { get; set; }
    public bool Success { get; set; } = true;
    public string Message { get; set; } = string.Empty;

    [JsonIgnore] public ResultKind Kind { get; set; } = ResultKind.Ok;
    [JsonIgnore] public int? RetryAfterSeconds { get; set; }

    public static ServiceResponse<T> Fail(ResultKind kind, string message, int? retryAfterSeconds = null) =>
        new() { Success = false, Kind = kind, Message = message, RetryAfterSeconds = retryAfterSeconds };
}

public static class ServiceGuard
{
    /// <summary>Converts expected failures to responses and hides unexpected exception details from clients.</summary>
    public static async Task<ServiceResponse<T>> RunAsync<T>(Func<Task<ServiceResponse<T>>> action, Action<Exception> onUnexpected)
    {
        try
        {
            return await action();
        }
        catch (AuthException ex)
        {
            return ServiceResponse<T>.Fail(ex.Kind, ex.Message, ex.RetryAfterSeconds);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            onUnexpected(ex);
            return ServiceResponse<T>.Fail(ResultKind.ServerError, "An unexpected error occurred.");
        }
    }
}
