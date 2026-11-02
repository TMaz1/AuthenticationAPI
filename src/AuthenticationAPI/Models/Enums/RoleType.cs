using System.Text.Json.Serialization;

namespace AuthenticationAPI.Models.Enums;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RoleType
{
    Administrator = 1,
    Editor = 2,
    Author = 3,
    Seller = 4,
    Viewer = 5
}
