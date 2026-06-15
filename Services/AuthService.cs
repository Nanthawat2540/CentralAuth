using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CentralAuth.Models;
using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;

namespace CentralAuth.Services;

public interface IAuthService
{
    Task<CentralUser?> ValidateAsync(string login, string password);
    string             IssueToken(CentralUser user, string appId);
    TokenPayload?      VerifyToken(string token);
}

public class AuthService(IConfiguration config) : IAuthService
{
    private SqlConnection CreateConn() =>
        new(config.GetConnectionString("CentralAuth"));

    private string JwtSecret => config["Jwt:Secret"]
        ?? throw new InvalidOperationException("Jwt:Secret missing");

    private int JwtMinutes => int.TryParse(config["Jwt:ExpiresMinutes"], out var m) ? m : 480;

    public async Task<CentralUser?> ValidateAsync(string login, string password)
    {
        using var db = CreateConn();
        var user = await db.QueryFirstOrDefaultAsync<CentralUser>(
            "sp_Auth_GetUserByLogin",
            new { login },
            commandType: CommandType.StoredProcedure);

        if (user is null || !user.IsActive) return null;
        if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash)) return null;

        await db.ExecuteAsync("sp_Auth_UpdateLastLogin",
            new { user_id = user.Id },
            commandType: CommandType.StoredProcedure);

        return user;
    }

    public string IssueToken(CentralUser user, string appId)
    {
        var key     = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret));
        var creds   = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var claims  = new[]
        {
            new Claim("uid",          user.Id.ToString()),
            new Claim("username",     user.Username),
            new Claim("email",        user.Email ?? ""),
            new Claim("display_name", user.DisplayName ?? user.Username),
            new Claim("role",         user.Role),
            new Claim("app_id",       appId),
        };
        var token = new JwtSecurityToken(
            issuer:   "central-auth",
            audience: appId,
            claims:   claims,
            expires:  DateTime.UtcNow.AddMinutes(JwtMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public TokenPayload? VerifyToken(string token)
    {
        try
        {
            var key     = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret));
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer           = true,
                ValidIssuer              = "central-auth",
                ValidateAudience         = false,
                ValidateLifetime         = true,
                IssuerSigningKey         = key,
                ClockSkew                = TimeSpan.Zero,
            }, out var validated);

            var jwt = (JwtSecurityToken)validated;
            return new TokenPayload
            {
                UserId      = int.Parse(jwt.Claims.First(c => c.Type == "uid").Value),
                Username    = jwt.Claims.First(c => c.Type == "username").Value,
                Email       = jwt.Claims.First(c => c.Type == "email").Value,
                DisplayName = jwt.Claims.First(c => c.Type == "display_name").Value,
                Role        = jwt.Claims.First(c => c.Type == "role").Value,
                AppId       = jwt.Claims.First(c => c.Type == "app_id").Value,
            };
        }
        catch { return null; }
    }
}
