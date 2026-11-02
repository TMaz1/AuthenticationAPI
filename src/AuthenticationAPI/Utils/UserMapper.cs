using AuthenticationAPI.Dtos;
using AuthenticationAPI.Models;

namespace AuthenticationAPI.Utils;

public static class UserMapper
{
    public static UserResponse MapToUserResponse(User user)
    {
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), "User cannot be null.");
        }

        return new UserResponse
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            PhoneNumber = user.PhoneNumber,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt,
            IsActive = user.IsActive
        };
    }
}
