using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthWithJwt.Models;
using AuthWithJwt.Settings;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthWithJwt.Services;

public class JwtService
{
    private readonly JWTSettings _jwtSettings;
    private ILogger<JwtService> _logger;
    private readonly TokenValidationParameters _tokenValidationParameters;


    public JwtService(IOptions<JWTSettings> jwtSettings, ILogger<JwtService> logger)
    {
        _logger = logger;
        _jwtSettings = jwtSettings.Value;
        
        _tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey)),
            ValidateIssuer = true,
            ValidIssuer = _jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtSettings.Audience,
            ValidateLifetime = true // Проверяет срок действия токена
        };
    }

    public string GenerateToken(User user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Name)
        };

        var token = new JwtSecurityToken(
            _jwtSettings.Issuer,
            _jwtSettings.Audience,
            claims,
            expires: DateTime.Now.AddMinutes(1),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey)),
                SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<string> ReissueTokenAsync(string existingToken)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var secretKey = _jwtSettings.SecretKey;
            var key = Encoding.UTF8.GetBytes(secretKey!);
            
            var principal = tokenHandler.ValidateToken(existingToken, _tokenValidationParameters, out _);

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var userName = principal.FindFirst(ClaimTypes.Name)?.Value;

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(userName))
                _logger.LogError("Token does not contain required claims");
            
            var newTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity([
                    new Claim(ClaimTypes.NameIdentifier, userId),
                    new Claim(ClaimTypes.Name, userName)
                ]),
                Expires = DateTime.UtcNow.AddMinutes(1),
                Audience = _jwtSettings.Audience,
                Issuer = _jwtSettings.Issuer,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var newToken = tokenHandler.CreateToken(newTokenDescriptor);
            return await Task.FromResult(tokenHandler.WriteToken(newToken));
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}