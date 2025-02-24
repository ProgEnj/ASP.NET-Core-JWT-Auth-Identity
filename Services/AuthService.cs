using System.Data;
using System.Security.Claims;
using System.Text;
using ControllersTest.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace ControllersTest.Services;

public class AuthService : IAuthService
{
    private readonly IConfiguration _configuration;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ITokenService _tokenService;
    private readonly ApplicationDbContext _context;
    private readonly IEmailSender<ApplicationUser> _emailSender;
    private readonly LinkGenerator _linkGenerator;

    private readonly string confirmEmailEndpointName = "auth/confirmemail";
    private readonly string ResetPasswordEdpointName = "auth/resetpassword";

    public AuthService(LinkGenerator linkGenerator, IConfiguration configuration, 
        UserManager<ApplicationUser> userManager, ITokenService tokenService, ApplicationDbContext context, 
        IEmailSender<ApplicationUser> emailSender, RoleManager<IdentityRole> roleManager)
    {
        _linkGenerator = linkGenerator;
        _configuration = configuration;
        _userManager = userManager;
        _tokenService = tokenService;
        _context = context;
        _emailSender = emailSender;
        _roleManager = roleManager;
    }

    public async Task<ApplicationUser> RegisterAsync(UserRegisterDTO request, HttpContext ctx)
    {
        // TODO: move this somewhere else
        if (!await _roleManager.RoleExistsAsync("Admin"))
        {
            _roleManager.CreateAsync(new IdentityRole("Admin"));
        }
        
        if (await _userManager.FindByEmailAsync(request.Email) != null)
        {
            throw new Exception("Requested email already exists");
            return null;
            // TODO: to have refreshToken and refreshToken logic
            //  other endpoints, admin endpoint
        }
        
        var newUser = new ApplicationUser(){ UserName = request.UserName, Email = request.Email};
        
        var result = await _userManager.CreateAsync(newUser, request.Password);
        if (result == IdentityResult.Failed())
        {
            throw new Exception("User creation has failed");
        }
       
        //await SendConfirmationEmailAsync(newUser, ctx);
        return newUser;
    }
    
    public async Task<UserInfoDTO> LoginAsync(UserLoginDTO request, HttpContext ctx)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            throw new Exception("Invalid username or password");
            return null;
        }

        if (!await _userManager.CheckPasswordAsync(user, request.Password))
        {
            throw new Exception("Invalid username or password");
            return null;
        }

        var token = await _tokenService.GenerateTokenAsync(user);
        var refreshToken = _tokenService.GenerateRefreshToken();
        
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpires = DateTime.UtcNow.AddDays(30);
        await _userManager.UpdateAsync(user);
        
        var claims = new List<Claim>() { new Claim("refreshToken", refreshToken) };
        await ctx.SignInAsync("refreshTokenCookie", new ClaimsPrincipal(new ClaimsIdentity(claims, "refreshToken")));
        
        return new UserInfoDTO(user.Id, user.UserName, user.Email, token, refreshToken);
    }

    public async Task<ApplicationUser> LogoutUserAsync(HttpContext ctx)
    {
        string? refreshToken = ctx.User.FindFirstValue("refreshToken");
        if(refreshToken == null)
        {
            throw new Exception("There is no refresh token in request");
            return null;
        }
        
        var user = await _userManager.Users.FirstAsync(u => u.RefreshToken == refreshToken);
        if (user == null)
        {
            throw new Exception("There is no such user with provided refreshToken");
            return null;
        }
        
        user.RefreshToken = null;
        await ctx.SignOutAsync("refreshTokenCookie");
        return user;
    }

    public async Task SendConfirmationEmailAsync(ApplicationUser user, HttpContext ctx)
    {
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var routeValues = new RouteValueDictionary()
        {
            ["userId"] = user.Id,
            ["code"] = code,
        };

        var confirmEmailURL = _linkGenerator.GetUriByName(ctx, confirmEmailEndpointName, routeValues);
        await _emailSender.SendConfirmationLinkAsync(user, user.Email, confirmEmailURL);
    }

    public async Task<ApplicationUser> ConfirmEmailAsync(string userId, string code)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new Exception("There is no such user with provided userId");
            return null;
        }
        code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        
        if(await _userManager.ConfirmEmailAsync(user, code) == IdentityResult.Failed());
        {
            throw new Exception("Failed to confirm Email");
            return null;
        }
        return user;
    }

    public async Task<ApplicationUser> ForgotPasswordEmailAsync(ForgotPasswordDTO request, HttpContext ctx)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            throw new Exception("There is no such user with provided email");
            return null;
        }

        var code = await _userManager.GeneratePasswordResetTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
        
        var routeValues = new RouteValueDictionary()
        {
            ["userId"] = user.Id,
            ["code"] = code,
        };

        var confirmEmailURL = _linkGenerator.GetUriByName(ctx, ResetPasswordEdpointName, routeValues);
        await _emailSender.SendPasswordResetLinkAsync(user, user.Email, code);
        return user;
    }
    
    public async Task<ApplicationUser> ResetPasswordAsync(ResetPasswordDTO request, HttpContext ctx)
    {
        var user = await _userManager.FindByIdAsync(request.Id);
        if (user == null)
        {
            throw new Exception("There is no such user with provided userId");
            return null;
        }
        if (!user.EmailConfirmed)
        {
            throw new Exception("Email is not confirmed");
            return null;
        }
        
        var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.resetCode));
        if (await _userManager.ResetPasswordAsync(user, code, request.newPassword) == IdentityResult.Failed())
        {
            throw new Exception("Failed to change password");
            return null;
        }

        await this.LogoutUserAsync(ctx);
        return user;
    }

    public async Task<string?> RefreshAccessTokenAsync(HttpContext ctx)
    {
        string? refreshToken = ctx.User.FindFirstValue("refreshToken");
        if(refreshToken == null)
        {
            throw new Exception("There is no refresh token in request");
            return null;
        }
        
        var user = await _userManager.Users.FirstAsync(u => u.RefreshToken == refreshToken);
        if (user == null)
        {
            throw new Exception("User with provided refreshToken does not exist");
            return null;
        }

        var newRefreshToken = await _tokenService.GenerateTokenAsync(user);
        user.RefreshToken = newRefreshToken;
        
        return await _tokenService.GenerateTokenAsync(user);
    } 
}