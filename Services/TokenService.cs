using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CentralAuth.Models;
using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace CentralAuth.Services;

public interface ITokenService
{
    string         IssueAccessToken(CentralUser user, string? appId = null);
    Task<string>   IssueRefreshTokenAsync(int userId, string? ip, string? ua, CancellationToken ct = default);
    TokenPayload?  ValidateAccessToken(string token);
    Task<(CentralUser? user, string? newRefreshToken)> RotateRefreshTokenAsync(string refreshToken, string? ip, string? ua, CancellationToken ct = default);
    Task           RevokeRefreshTokenAsync(string refreshToken, CancellationToken ct = default);
    Task           RevokeAllUserTokensAsync(int userId, CancellationToken ct = default);
    Task           BlacklistAccessTokenAsync(string token, CancellationToken ct = default);
    Task<bool>     IsAccessTokenBlacklistedAsync(string token, CancellationToken ct = default);
}

public class TokenService(IConfiguration config, IDbConnectionFactory db, IDistributedCache cache) : ITokenService
{
    private string JwtSecret     => config["Jwt:Secret"] ?? throw new InvalidOperationException("Jwt:Secret missing");
    private int    AccessMinutes => int.TryParse(config["Jwt:AccessExpireMinutes"], out var m) ? m : 60;
    private int    RefreshDays   => int.TryParse(config["Jwt:RefreshExpireDays"],   out var d) ? d : 30;

    public string IssueAccessToken(CentralUser user, string? appId = null)
    {
        var key    = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret));
        var creds  = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now    = DateTime.UtcNow;
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub,  user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti,  Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat,  new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim("uid",          user.Id.ToString()),
            new Claim("username",     user.Username),
            new Claim("email",        user.Email ?? ""),
            new Claim("display_name", user.DisplayName ?? user.Username),
            new Claim("role",         user.Role),
            new Claim("app_id",       appId ?? ""),
        };

        var token = new JwtSecurityToken(
            issuer:             "central-auth",
            audience:           appId ?? "all",
            claims:             claims,
            notBefore:          now,
            expires:            now.AddMinutes(AccessMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<string> IssueRefreshTokenAsync(int userId, string? ip, string? ua, CancellationToken ct = default)
    {
        var token     = GenerateSecureToken();
        var expiresAt = DateTime.UtcNow.AddDays(RefreshDays);

        using var conn = db.Create();
        await conn.ExecuteAsync(
            @"INSERT INTO refresh_tokens (user_id, token, expires_at, ip_address, user_agent, created_at)
              VALUES (@userId, @token, @expiresAt, @ip, @ua, GETUTCDATE())",
            new { userId, token, expiresAt, ip, ua });

        return token;
    }

    public TokenPayload? ValidateAccessToken(string token)
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

    public async Task<(CentralUser? user, string? newRefreshToken)> RotateRefreshTokenAsync(
        string refreshToken, string? ip, string? ua, CancellationToken ct = default)
    {
        using var conn = db.Create();

        var existing = await conn.QueryFirstOrDefaultAsync<RefreshToken>(
            @"SELECT id, user_id AS UserId, token AS Token, expires_at AS ExpiresAt,
                     revoked_at AS RevokedAt, replaced_by AS ReplacedBy
              FROM refresh_tokens WHERE token = @refreshToken",
            new { refreshToken });

        if (existing is null || !existing.IsActive)
            return (null, null);

        var user = await conn.QueryFirstOrDefaultAsync<CentralUser>(
            "SELECT id AS Id, username AS Username, email AS Email, password_hash AS PasswordHash, display_name AS DisplayName, role AS Role, is_active AS IsActive, mfa_enabled AS MfaEnabled FROM users WHERE id = @id AND is_active = 1",
            new { id = existing.UserId });

        if (user is null) return (null, null);

        var newToken  = GenerateSecureToken();
        var expiresAt = DateTime.UtcNow.AddDays(RefreshDays);
        var now       = DateTime.UtcNow;

        // Revoke old, insert new in one transaction
        await conn.ExecuteAsync(
            @"UPDATE refresh_tokens SET revoked_at = @now, replaced_by = @newToken WHERE id = @id;
              INSERT INTO refresh_tokens (user_id, token, expires_at, ip_address, user_agent, created_at)
              VALUES (@userId, @newToken, @expiresAt, @ip, @ua, GETUTCDATE());",
            new { now, newToken, id = existing.Id, userId = existing.UserId, expiresAt, ip, ua });

        return (user, newToken);
    }

    public async Task RevokeRefreshTokenAsync(string refreshToken, CancellationToken ct = default)
    {
        using var conn = db.Create();
        await conn.ExecuteAsync(
            "UPDATE refresh_tokens SET revoked_at = GETUTCDATE() WHERE token = @refreshToken AND revoked_at IS NULL",
            new { refreshToken });
    }

    public async Task RevokeAllUserTokensAsync(int userId, CancellationToken ct = default)
    {
        using var conn = db.Create();
        await conn.ExecuteAsync(
            "UPDATE refresh_tokens SET revoked_at = GETUTCDATE() WHERE user_id = @userId AND revoked_at IS NULL",
            new { userId });
    }

    public async Task BlacklistAccessTokenAsync(string token, CancellationToken ct = default)
    {
        var payload = ValidateAccessToken(token);
        if (payload is null) return;

        // Calculate remaining TTL
        var jwtObj  = new JwtSecurityTokenHandler().ReadJwtToken(token);
        var ttl     = jwtObj.ValidTo - DateTime.UtcNow;
        if (ttl <= TimeSpan.Zero) return;

        var jti = jwtObj.Id;
        await cache.SetStringAsync($"blacklist:{jti}", "1",
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, ct);
    }

    public async Task<bool> IsAccessTokenBlacklistedAsync(string token, CancellationToken ct = default)
    {
        try
        {
            var jwtObj = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var result = await cache.GetStringAsync($"blacklist:{jwtObj.Id}", ct);
            return result != null;
        }
        catch { return false; }
    }

    private static string GenerateSecureToken()
    {
        var bytes = new byte[64];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
}
