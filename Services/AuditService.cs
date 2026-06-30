using System.Text.Json;
using Dapper;

namespace CentralAuth.Services;

public interface IAuditService
{
    Task LogAsync(int? userId, string action, string? resource = null,
                  object? details = null, string? ip = null, string? ua = null,
                  CancellationToken ct = default);
}

public class AuditService(IDbConnectionFactory db, ILogger<AuditService> logger) : IAuditService
{
    public async Task LogAsync(int? userId, string action, string? resource = null,
        object? details = null, string? ip = null, string? ua = null, CancellationToken ct = default)
    {
        try
        {
            var detailsJson = details is null ? null : JsonSerializer.Serialize(details);
            using var conn  = db.Create();
            await conn.ExecuteAsync(
                @"INSERT INTO audit_logs (user_id, action, resource, details, ip_address, user_agent, created_at)
                  VALUES (@userId, @action, @resource, @detailsJson, @ip, @ua, GETUTCDATE())",
                new { userId, action, resource, detailsJson, ip, ua });
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to write audit log for action {Action}", action);
        }
    }
}
