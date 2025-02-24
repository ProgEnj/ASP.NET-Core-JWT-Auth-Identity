using ControllersTest.Model;
using Microsoft.AspNetCore.Identity;

namespace ControllersTest.Services;

public interface IAuthService
{
    Task<ApplicationUser?> RegisterAsync(UserRegisterDTO request, HttpContext ctx);
    Task<UserInfoDTO> LoginAsync(UserLoginDTO request, HttpContext ctx);
    Task<ApplicationUser> ConfirmEmailAsync(string userId, string code);
    Task SendConfirmationEmailAsync(ApplicationUser user, HttpContext ctx);
    Task<ApplicationUser> ForgotPasswordEmailAsync(ForgotPasswordDTO request, HttpContext ctx);
    Task<ApplicationUser> ResetPasswordAsync(ResetPasswordDTO request, HttpContext ctx);
    Task<string?> RefreshAccessTokenAsync(HttpContext ctx);
    Task<ApplicationUser> LogoutUserAsync(HttpContext ctx);
}