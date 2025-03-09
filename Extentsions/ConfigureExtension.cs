using System.Text;
using ControllersTest.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace ControllersTest.Extentsions;

public static class ConfigureExtension
{
    public static void AddConfiguredIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentityCore<ApplicationUser>(o =>
            {
                o.SignIn.RequireConfirmedAccount = false;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
    }

    public static void AddConfiguredAuthentication(this IServiceCollection services, IConfiguration configuration)
    {

        services.AddAuthentication(o =>
            {
                o.RequireAuthenticatedSignIn = false;
                o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(o =>
            {
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = configuration["JwtSettings:Issuer"] != null,
                    ValidIssuer = configuration["JwtSettings:Issuer"],
                    ValidateAudience = configuration["JwwtSettings:Audience"] != null,
                    ValidAudience = configuration["JwtSettings:Audience"],
                    ValidateLifetime = true,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(configuration["JwtSettings:Token"])),
                    ValidateIssuerSigningKey = true
                };
            })
            .AddCookie("refreshTokenCookie", o =>
            {
                o.Cookie.Name = "refreshToken";
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Strict;
                o.Cookie.Path = "auth/refreshaccess";
                o.ExpireTimeSpan = TimeSpan.FromDays(30);
            });
    }
    
    public static void AddConfiguredAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthorization(o =>
        {
            // TODO: Probably add policies as constants or just somewhere else
            o.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"));
            o.AddPolicy("RefreshTokenPolicy", policy => policy.RequireClaim("refreshToken"));
        });
    }
}