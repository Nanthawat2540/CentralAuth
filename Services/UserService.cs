using System.Data;
using CentralAuth.Models;
using Dapper;

namespace CentralAuth.Services;

public interface IUserService
{
    Task<CentralUser?>       GetByIdAsync(int id, CancellationToken ct = default);
    Task<CentralUser?>       GetByLoginAsync(string login, CancellationToken ct = default);
    Task<PagedResult<UserDto>> GetUsersAsync(int page, int pageSize, string? search, CancellationToken ct = default);
    Task<UserDto>            CreateAsync(CreateUserRequest req, CancellationToken ct = default);
    Task<UserDto?>           UpdateAsync(int id, UpdateUserRequest req, CancellationToken ct = default);
    Task<bool>               DeleteAsync(int id, CancellationToken ct = default);
    Task<bool>               ChangePasswordAsync(int id, string currentPassword, string newPassword, CancellationToken ct = default);
    Task                     UpdateLastLoginAsync(int id, CancellationToken ct = default);
    Task<bool>               UsernameExistsAsync(string username, CancellationToken ct = default);
    Task<bool>               EmailExistsAsync(string email, CancellationToken ct = default);
}

public class UserService(IDbConnectionFactory db) : IUserService
{
    public async Task<CentralUser?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        using var conn = db.Create();
        return await conn.QueryFirstOrDefaultAsync<CentralUser>(
            @"SELECT id AS Id, username AS Username, email AS Email, password_hash AS PasswordHash,
                     display_name AS DisplayName, role AS Role, is_active AS IsActive, mfa_enabled AS MfaEnabled
              FROM users WHERE id = @id",
            new { id });
    }

    public async Task<CentralUser?> GetByLoginAsync(string login, CancellationToken ct = default)
    {
        using var conn = db.Create();
        return await conn.QueryFirstOrDefaultAsync<CentralUser>(
            @"SELECT TOP 1
                     id AS Id, username AS Username, email AS Email, password_hash AS PasswordHash,
                     display_name AS DisplayName, role AS Role, is_active AS IsActive, mfa_enabled AS MfaEnabled
              FROM users
              WHERE is_active = 1 AND (username = @login OR email = @login)",
            new { login });
    }

    public async Task<PagedResult<UserDto>> GetUsersAsync(int page, int pageSize, string? search, CancellationToken ct = default)
    {
        using var conn = db.Create();
        var offset = (page - 1) * pageSize;
        var where  = string.IsNullOrWhiteSpace(search)
            ? ""
            : "WHERE username LIKE @q OR email LIKE @q OR display_name LIKE @q";
        var param  = new { q = $"%{search}%", offset, pageSize };

        var total = await conn.ExecuteScalarAsync<int>($"SELECT COUNT(*) FROM users {where}", param);
        var items = await conn.QueryAsync<UserDto>(
            $@"SELECT id AS Id, username AS Username, email AS Email, display_name AS DisplayName,
                      role AS Role, is_active AS IsActive, mfa_enabled AS MfaEnabled,
                      last_login AS LastLogin, created_at AS CreatedAt
               FROM users {where}
               ORDER BY id DESC
               OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY", param);

        return new PagedResult<UserDto>(items.ToList(), total, page, pageSize);
    }

    public async Task<UserDto> CreateAsync(CreateUserRequest req, CancellationToken ct = default)
    {
        var hash = BCrypt.Net.BCrypt.HashPassword(req.Password, workFactor: 12);
        using var conn = db.Create();
        var id = await conn.ExecuteScalarAsync<int>(
            @"INSERT INTO users (username, email, password_hash, display_name, role, is_active, created_at, updated_at)
              OUTPUT INSERTED.id
              VALUES (@username, @email, @hash, @displayName, @role, 1, GETUTCDATE(), GETUTCDATE())",
            new { username = req.Username, email = req.Email, hash, displayName = req.DisplayName ?? req.Username, role = req.Role });

        return (await GetByIdAsync(id, ct))!.ToDto();
    }

    public async Task<UserDto?> UpdateAsync(int id, UpdateUserRequest req, CancellationToken ct = default)
    {
        using var conn = db.Create();
        var sets   = new List<string>();
        var param  = new Dapper.DynamicParameters();
        param.Add("id", id);

        if (req.Email       is not null) { sets.Add("email = @email");            param.Add("email",       req.Email); }
        if (req.DisplayName is not null) { sets.Add("display_name = @displayName"); param.Add("displayName", req.DisplayName); }
        if (req.Role        is not null) { sets.Add("role = @role");              param.Add("role",        req.Role); }
        if (req.IsActive    is not null) { sets.Add("is_active = @isActive");     param.Add("isActive",    req.IsActive); }

        if (sets.Count == 0) return (await GetByIdAsync(id, ct))?.ToDto();

        sets.Add("updated_at = GETUTCDATE()");
        await conn.ExecuteAsync($"UPDATE users SET {string.Join(", ", sets)} WHERE id = @id", param);
        return (await GetByIdAsync(id, ct))?.ToDto();
    }

    public async Task<bool> DeleteAsync(int id, CancellationToken ct = default)
    {
        using var conn = db.Create();
        var rows = await conn.ExecuteAsync(
            "UPDATE users SET is_active = 0, updated_at = GETUTCDATE() WHERE id = @id", new { id });
        return rows > 0;
    }

    public async Task<bool> ChangePasswordAsync(int id, string currentPassword, string newPassword, CancellationToken ct = default)
    {
        var user = await GetByIdAsync(id, ct);
        if (user is null) return false;
        if (!BCrypt.Net.BCrypt.Verify(currentPassword, user.PasswordHash)) return false;

        var hash = BCrypt.Net.BCrypt.HashPassword(newPassword, workFactor: 12);
        using var conn = db.Create();
        await conn.ExecuteAsync(
            "UPDATE users SET password_hash = @hash, updated_at = GETUTCDATE() WHERE id = @id",
            new { hash, id });
        return true;
    }

    public async Task UpdateLastLoginAsync(int id, CancellationToken ct = default)
    {
        using var conn = db.Create();
        await conn.ExecuteAsync(
            "UPDATE users SET last_login = GETUTCDATE() WHERE id = @id", new { id });
    }

    public async Task<bool> UsernameExistsAsync(string username, CancellationToken ct = default)
    {
        using var conn = db.Create();
        return await conn.ExecuteScalarAsync<bool>("SELECT CAST(COUNT(*) AS BIT) FROM users WHERE username = @username", new { username });
    }

    public async Task<bool> EmailExistsAsync(string email, CancellationToken ct = default)
    {
        using var conn = db.Create();
        return await conn.ExecuteScalarAsync<bool>("SELECT CAST(COUNT(*) AS BIT) FROM users WHERE email = @email", new { email });
    }
}

// Extension method for mapping
public static class UserExtensions
{
    public static UserDto ToDto(this CentralUser u) => new(
        u.Id, u.Username, u.Email, u.DisplayName, u.Role,
        u.IsActive, u.MfaEnabled, null, DateTime.MinValue);
}
