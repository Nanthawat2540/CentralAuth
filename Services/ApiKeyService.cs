using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CentralAuth.Models;
using Dapper;

namespace CentralAuth.Services;

public interface IApiKeyService
{
    Task<(ApiKeyResponse response, string rawKey)> CreateAsync(CreateApiKeyRequest req, int? userId, CancellationToken ct = default);
    Task<ApiKey?>                  ValidateAsync(string rawKey, CancellationToken ct = default);
    Task<List<ApiKeyResponse>>     GetByUserAsync(int userId, CancellationToken ct = default);
    Task<bool>                     RevokeAsync(int id, int? userId, CancellationToken ct = default);
    Task                           RecordUsageAsync(int id, CancellationToken ct = default);
}

public class ApiKeyService(IDbConnectionFactory db) : IApiKeyService
{
    public async Task<(ApiKeyResponse response, string rawKey)> CreateAsync(
        CreateApiKeyRequest req, int? userId, CancellationToken ct = default)
    {
        var rawKey  = GenerateApiKey();
        var keyHash = HashKey(rawKey);
        var perms   = req.Permissions is { Count: > 0 }
            ? JsonSerializer.Serialize(req.Permissions)
            : null;

        using var conn = db.Create();
        var id = await conn.ExecuteScalarAsync<int>(
            @"INSERT INTO api_keys (key_hash, name, user_id, app_id, permissions, expires_at, is_active, created_at)
              OUTPUT INSERTED.id
              VALUES (@keyHash, @name, @userId, @appId, @perms, @expiresAt, 1, GETUTCDATE())",
            new { keyHash, name = req.Name, userId, appId = req.AppId, perms, expiresAt = req.ExpiresAt });

        var response = new ApiKeyResponse(id, req.Name, req.AppId, rawKey, perms,
            req.ExpiresAt, null, true, DateTime.UtcNow);
        return (response, rawKey);
    }

    public async Task<ApiKey?> ValidateAsync(string rawKey, CancellationToken ct = default)
    {
        var keyHash = HashKey(rawKey);
        using var conn = db.Create();
        var key = await conn.QueryFirstOrDefaultAsync<ApiKey>(
            @"SELECT id AS Id, key_hash AS KeyHash, name AS Name, user_id AS UserId, app_id AS AppId,
                     permissions AS Permissions, expires_at AS ExpiresAt, last_used AS LastUsed,
                     is_active AS IsActive, created_at AS CreatedAt
              FROM api_keys
              WHERE key_hash = @keyHash AND is_active = 1
                AND (expires_at IS NULL OR expires_at > GETUTCDATE())",
            new { keyHash });

        if (key is not null) await RecordUsageAsync(key.Id, ct);
        return key;
    }

    public async Task<List<ApiKeyResponse>> GetByUserAsync(int userId, CancellationToken ct = default)
    {
        using var conn = db.Create();
        var keys = await conn.QueryAsync<ApiKeyResponse>(
            @"SELECT id AS Id, name AS Name, app_id AS AppId, NULL AS Key, permissions AS Permissions,
                     expires_at AS ExpiresAt, last_used AS LastUsed, is_active AS IsActive, created_at AS CreatedAt
              FROM api_keys WHERE user_id = @userId ORDER BY created_at DESC",
            new { userId });
        return keys.ToList();
    }

    public async Task<bool> RevokeAsync(int id, int? userId, CancellationToken ct = default)
    {
        using var conn = db.Create();
        var where = userId.HasValue ? "AND (user_id = @userId OR @userId IS NULL)" : "";
        var rows  = await conn.ExecuteAsync(
            $"UPDATE api_keys SET is_active = 0 WHERE id = @id {where}",
            new { id, userId });
        return rows > 0;
    }

    public async Task RecordUsageAsync(int id, CancellationToken ct = default)
    {
        using var conn = db.Create();
        await conn.ExecuteAsync(
            "UPDATE api_keys SET last_used = GETUTCDATE() WHERE id = @id", new { id });
    }

    private static string GenerateApiKey()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return "ca_" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string HashKey(string key)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
