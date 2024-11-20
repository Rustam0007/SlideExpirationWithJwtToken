using AuthWithJwt.Models;
using AuthWithJwt.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthWithJwt.Controllers;


[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase
{
    private readonly JwtService _jwtService;

    public UserController(JwtService jwtService)
    {
        _jwtService = jwtService;
    }

    private static readonly List<User> Users = new()
    {
        new User(1, "Alice", "123"),
        new User(2, "Bob", "12345"),
        new User(3, "Charlie", "qwerty"),
    };

    [HttpPost("login")]
    public string Login([FromBody] LoginRequest loginRequest)
    {
        var user = Users.FirstOrDefault(u => u.Name == loginRequest.Name && u.Password == loginRequest.Password);
        if (user is null)
        {
            return "Invalid username or password";
        }
        
        var token = _jwtService.GenerateToken(user);
        return token;
    }
    
    
    [HttpGet]
    [Route("/users")]
    [Authorize]
    public IActionResult GetUsers()
    {
        return Ok(Users);
    }
    
}