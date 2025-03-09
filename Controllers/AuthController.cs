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
    [Route("[controller]")]
    public class AuthController(IAuthService _authService) : ControllerBase
    {
        [HttpPost("register")]
        [ProducesResponseType(typeof(void), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> RegisterUser([FromBody] UserRegisterDTO request)
        {
            var result = await _authService.RegisterAsync(request, HttpContext);
            return result.IsSuccess ? Ok() : BadRequest();
        }
        
        [HttpPost("login")]
        [ProducesResponseType(typeof(UserInfoDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> LoginUser([FromBody] UserLoginDTO request)
        {
            var result = await _authService.LoginAsync(request, HttpContext);
            return result.IsSuccess ? Ok(result.Value) : BadRequest();
        }
        
        [HttpPost("logout")]
        [ProducesResponseType(typeof(void), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [Authorize(AuthenticationSchemes = "refreshTokenCookie", Policy = "RefreshTokenPolicy")]
        public async Task<IActionResult> LogoutUser()
        {
            var result = await _authService.LogoutUserAsync(HttpContext);
            return result.IsSuccess ? Ok() : BadRequest();
        }
        
        [HttpPost("confirmemail")] 
        [ProducesResponseType(typeof(void), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string code)
        {
            var result = await _authService.ConfirmEmailAsync(userId, code);
            return result.IsSuccess ? Ok() : BadRequest();
        }
        
        [HttpPost("forgotpassword")]
        [ProducesResponseType(typeof(void), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [Authorize]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDTO request)
        {
            var result = await _authService.ForgotPasswordEmailAsync(request, this.HttpContext);
            return result.IsSuccess ? Ok() : BadRequest();
        }
        
        [HttpPost("resetpassword")]
        [ProducesResponseType(typeof(void), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO request)
        {
            var result = await _authService.ResetPasswordAsync(request, HttpContext);
            return result.IsSuccess ? Ok() : BadRequest();
        }
        
        [HttpGet("refreshaccess")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [Authorize(AuthenticationSchemes = "refreshTokenCookie", Policy = "RefreshTokenPolicy")]
        public async Task<IActionResult> RefreshAccess()
        {
            var result = await _authService.RefreshAccessTokenAsync(HttpContext);
            return result.IsSuccess ? Ok(result.Value) : BadRequest();
        }
    }
}
