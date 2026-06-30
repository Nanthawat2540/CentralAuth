using System.ComponentModel.DataAnnotations;

namespace CentralAuth.Models;

// ── Auth Requests ─────────────────────────────────────────────────────────

public record LoginRequest(
    [Required] string Login,
    [Required] string Password,
    string? AppId = null,
    bool   Remember = false
);

public record RegisterRequest(
    [Required][StringLength(50, MinimumLength = 3)] string Username,
    [Required][EmailAddress] string Email,
    [Required][StringLength(100, MinimumLength = 6)] string Password,
    string? DisplayName = null
);

public record RefreshRequest(
    [Required] string RefreshToken
);

public record ChangePasswordRequest(
    [Required] string CurrentPassword,
    [Required][StringLength(100, MinimumLength = 6)] string NewPassword
);

public record ForgotPasswordRequest(
    [Required][EmailAddress] string Email
);

public record ResetPasswordRequest(
    [Required] string Token,
    [Required][StringLength(100, MinimumLength = 6)] string NewPassword
);

public record MfaVerifyRequest(
    [Required] string Code
);

// ── Auth Responses ────────────────────────────────────────────────────────

public record AuthResponse(
    string      AccessToken,
    string      RefreshToken,
    DateTime    ExpiresAt,
    UserDto     User
);

public record TokenValidationResponse(
    bool    Valid,
    UserDto? User = null,
    string? Error = null
);

// ── User DTOs ─────────────────────────────────────────────────────────────

public record UserDto(
    int     Id,
    string  Username,
    string? Email,
    string? DisplayName,
    string  Role,
    bool    IsActive,
    bool    MfaEnabled,
    DateTime? LastLogin,
    DateTime CreatedAt
);

public record CreateUserRequest(
    [Required][StringLength(50, MinimumLength = 3)] string Username,
    [Required][EmailAddress] string Email,
    [Required][StringLength(100, MinimumLength = 6)] string Password,
    string? DisplayName = null,
    string  Role = "user"
);

public record UpdateUserRequest(
    string? Email,
    string? DisplayName,
    string? Role,
    bool?   IsActive
);

// ── Role & Permission DTOs ────────────────────────────────────────────────

public record RoleDto(
    string              Name,
    List<PermissionDto> Permissions
);

public record PermissionDto(
    int    Id,
    string Name,
    string Module,
    string Action,
    string? Description
);

public record AssignPermissionsRequest(
    [Required] List<int> PermissionIds
);

// ── API Key DTOs ──────────────────────────────────────────────────────────

public record CreateApiKeyRequest(
    [Required][StringLength(100, MinimumLength = 3)] string Name,
    string?    AppId = null,
    List<string>? Permissions = null,
    DateTime?  ExpiresAt = null
);

public record ApiKeyResponse(
    int      Id,
    string   Name,
    string?  AppId,
    string?  Key,          // Only shown once on creation
    string?  Permissions,
    DateTime? ExpiresAt,
    DateTime? LastUsed,
    bool     IsActive,
    DateTime CreatedAt
);

// ── Common Responses ──────────────────────────────────────────────────────

public record ApiResult<T>(bool Success, T? Data, string? Message = null);
public record PagedResult<T>(List<T> Items, int Total, int Page, int PageSize);
