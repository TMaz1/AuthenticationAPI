namespace AuthenticationAPI.Utils.Logger;

public interface IAppLogger<T>
{
    void Info(string messageTemplate, params object[] values);
    void Warn(string messageTemplate, params object[] values);
    void Error(Exception ex, string messageTemplate, params object[] values);
    void Debug(string messageTemplate, params object[] values);
}
