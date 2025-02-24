using ControllersTest.Model;
using Microsoft.AspNetCore.Identity;

namespace ControllersTest.Services;

public interface ITokenService
{
    Task<string> GenerateTokenAsync(ApplicationUser user);

    string GenerateRefreshToken();
}