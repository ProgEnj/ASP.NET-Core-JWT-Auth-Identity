using Microsoft.AspNetCore.Identity;

namespace ControllersTest.Model;

public class ApplicationUser : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpires { get; set; }
}