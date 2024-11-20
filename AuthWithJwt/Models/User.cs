namespace AuthWithJwt.Models;

public sealed record User(int Id, string Name, string Password);

public sealed record LoginRequest(string Name, string Password);
public sealed record LoginResponse(string Token);