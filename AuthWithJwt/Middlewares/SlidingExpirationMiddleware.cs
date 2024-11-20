using System.IdentityModel.Tokens.Jwt;
using AuthWithJwt.Services;

namespace AuthWithJwt.Middlewares;

public class SlidingExpirationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SlidingExpirationMiddleware> _logger;

    public SlidingExpirationMiddleware(RequestDelegate next,
        ILogger<SlidingExpirationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context, JwtService jwtTokenService)
    {
        try
        {
            string authorization = context.Request.Headers["Authorization"];


            JwtSecurityToken token = null;
            if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer"))
                token = new JwtSecurityTokenHandler().ReadJwtToken(authorization[7..]); // trim 'Bearer ' from the start

            if (token != null && token.ValidTo > DateTime.UtcNow)
            {
                TimeSpan timeElapsed = DateTime.UtcNow.Subtract(token.ValidFrom); // Time elapsed since token was created
                TimeSpan timeRemaining = token.ValidTo.Subtract(DateTime.UtcNow); // Time remaining before token expires

                if (timeRemaining < timeElapsed)
                {
                    var existingToken = authorization[7..];
                    var newToken = await jwtTokenService.ReissueTokenAsync(existingToken);
                    context.Response.Headers.Add("Set-Authorization", newToken);
                }
            }
        }
        catch(Exception e)
        {
            _logger.LogError(e, e.Message);
        }
        await _next(context);
    }
}