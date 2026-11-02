using System.Text.Json.Serialization;

namespace AuthenticationAPI.Models.Enums;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MfaMethodType
{
    Totp = 1,     // authenticator app
    Email = 2,
    Sms = 3       // SMS one-time code (disabled unless Security:Mfa:SmsEnabled)
}
