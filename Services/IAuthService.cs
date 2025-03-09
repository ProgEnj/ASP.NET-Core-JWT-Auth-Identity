using ControllersTest.Model;
using Microsoft.AspNetCore.Identity;

namespace ControllersTest.Services;

public interface IAuthService
{
    Task<Result> RegisterAsync(UserRegisterDTO request, HttpContext ctx);
    Task<Result<UserInfoDTO>> LoginAsync(UserLoginDTO request, HttpContext ctx);
    Task<Result> ConfirmEmailAsync(string userId, string code);
    Task<Result> SendConfirmationEmailAsync(ApplicationUser user, HttpContext ctx);
    Task<Result> ForgotPasswordEmailAsync(ForgotPasswordDTO request, HttpContext ctx);
    Task<Result> ResetPasswordAsync(ResetPasswordDTO request, HttpContext ctx);
    Task<Result<string>> RefreshAccessTokenAsync(HttpContext ctx);
    Task<Result> LogoutUserAsync(HttpContext ctx);
}