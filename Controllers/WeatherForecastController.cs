using ControllersTest.Model;
using ControllersTest.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ControllersTest.Controllers;
    
[ApiController]
[Route("[controller]")]
public class WeatherForecastController(IAuthService _auth) : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    [HttpGet("GetWeatherForecast")]
    public IEnumerable<WeatherForecast> GetForecast()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }
    
    [Authorize]
    [HttpGet]
    public IActionResult Get()
    {
        return Ok("Congrats! You are an user");
    }
    
    [HttpGet("GetAdmin")]
    [Authorize(Policy = "AdminPolicy")]
    public string GetAdmin()
    {
        return "Congrats! You are an admin";
    }
}
