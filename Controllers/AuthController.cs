using System.Security.Claims;
using ControllersTest.Model;
using ControllersTest.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ControllersTest.Controllers
{
    [ApiController]
    [Route("[controller]/")]
    public class AuthController(IAuthService _authService) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] UserRegisterDTO request)
        {
            return await _authService.RegisterAsync(request, this.HttpContext) == null ? 
                    BadRequest() : Created();
        }
        
        [HttpPost("login")]
        public async Task<IActionResult> LoginUser([FromBody] UserLoginDTO request)
        {
            var result = await _authService.LoginAsync(request, HttpContext);
            return result == null ? Unauthorized() : Ok(result);
        }
        
        [HttpPost("logout")]
        [Authorize(AuthenticationSchemes = "refreshTokenCookie", Policy = "RefreshTokenPolicy")]
        public async Task<IActionResult> LogoutUser()
        {
            var result = await _authService.LogoutUserAsync(HttpContext);
            return result == null ? BadRequest() : Ok(result);
        }
        
        [HttpPost("confirmemail")] 
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string code)
        {
            var result = await _authService.ConfirmEmailAsync(userId, code);
            return result == null ? BadRequest() : Ok();
        }
        
        [HttpPost("forgotpassword")]
        [Authorize]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDTO request)
        {
            var result = await _authService.ForgotPasswordEmailAsync(request, this.HttpContext);
            return result == null ? BadRequest() : Ok();
        }
        
        [HttpPost("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO request)
        {
            var result = await _authService.ResetPasswordAsync(request, HttpContext);
            return result == null ? BadRequest() : Ok();
        }
        
        [HttpGet("refreshaccess")]
        [Authorize(AuthenticationSchemes = "refreshTokenCookie", Policy = "RefreshTokenPolicy")]
        public async Task<IActionResult> RefreshAccess()
        {
            var accessToken = await _authService.RefreshAccessTokenAsync(HttpContext);
            return accessToken == null ? NotFound() : Ok(accessToken);
        }
    }
}
