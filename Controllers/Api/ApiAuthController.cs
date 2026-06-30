using CentralAuth.Models;
using CentralAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CentralAuth.Controllers.Api;

[ApiController]
[Route("api/auth")]
[Produces("application/json")]
public class ApiAuthController(
    IUserService    users,
    ITokenService   tokens,
    IAuditService   audit,
    ILogger<ApiAuthController> logger) : ControllerBase
{
    private string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();
    private string? ClientUa => Request.Headers.UserAgent.ToString();

    // POST /api/auth/login
    [HttpPost("login")]
    [ProducesResponseType<AuthResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest req, CancellationToken ct)
    {
        var user = await users.GetByLoginAsync(req.Login, ct);
        if (user is null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
        {
            await audit.LogAsync(null, "login.failed", req.Login, new { reason = "invalid_credentials" }, ClientIp, ClientUa, ct);
            return Unauthorized(new { error = "Invalid credentials" });
        }

        if (!user.IsActive)
            return Unauthorized(new { error = "Account is disabled" });

        if (user.MfaEnabled)
            return Ok(new { mfaRequired = true, tempToken = IssueTempToken(user.Id) });

        await users.UpdateLastLoginAsync(user.Id, ct);
        var accessToken  = tokens.IssueAccessToken(user, req.AppId);
        var refreshToken = await tokens.IssueRefreshTokenAsync(user.Id, ClientIp, ClientUa, ct);

        await audit.LogAsync(user.Id, "login.success", null, new { appId = req.AppId }, ClientIp, ClientUa, ct);

        return Ok(new AuthResponse(
            AccessToken:  accessToken,
            RefreshToken: refreshToken,
            ExpiresAt:    DateTime.UtcNow.AddMinutes(60),
            User:         user.ToDto()
        ));
    }

    // POST /api/auth/register
    [HttpPost("register")]
    [ProducesResponseType<AuthResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req, CancellationToken ct)
    {
        if (await users.UsernameExistsAsync(req.Username, ct))
            return Conflict(new { error = "Username already taken" });
        if (await users.EmailExistsAsync(req.Email, ct))
            return Conflict(new { error = "Email already registered" });

        var createReq    = new CreateUserRequest(req.Username, req.Email, req.Password, req.DisplayName);
        var userDto      = await users.CreateAsync(createReq, ct);
        var user         = await users.GetByIdAsync(userDto.Id, ct);

        var accessToken  = tokens.IssueAccessToken(user!, null);
        var refreshToken = await tokens.IssueRefreshTokenAsync(user!.Id, ClientIp, ClientUa, ct);

        await audit.LogAsync(user.Id, "register", null, new { username = req.Username }, ClientIp, ClientUa, ct);

        return Created($"/api/users/{user.Id}", new AuthResponse(
            AccessToken:  accessToken,
            RefreshToken: refreshToken,
            ExpiresAt:    DateTime.UtcNow.AddMinutes(60),
            User:         userDto
        ));
    }

    // POST /api/auth/refresh
    [HttpPost("refresh")]
    [ProducesResponseType<AuthResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest req, CancellationToken ct)
    {
        var (user, newRefreshToken) = await tokens.RotateRefreshTokenAsync(req.RefreshToken, ClientIp, ClientUa, ct);
        if (user is null || newRefreshToken is null)
            return Unauthorized(new { error = "Invalid or expired refresh token" });

        var accessToken = tokens.IssueAccessToken(user);
        await audit.LogAsync(user.Id, "token.refreshed", null, null, ClientIp, ClientUa, ct);

        return Ok(new AuthResponse(
            AccessToken:  accessToken,
            RefreshToken: newRefreshToken,
            ExpiresAt:    DateTime.UtcNow.AddMinutes(60),
            User:         user.ToDto()
        ));
    }

    // POST /api/auth/logout
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Logout([FromBody] RefreshRequest? req, CancellationToken ct)
    {
        var accessToken = GetBearerToken();
        if (accessToken is not null)
            await tokens.BlacklistAccessTokenAsync(accessToken, ct);

        if (req?.RefreshToken is not null)
            await tokens.RevokeRefreshTokenAsync(req.RefreshToken, ct);

        var userId = GetCurrentUserId();
        if (userId > 0)
            await audit.LogAsync(userId, "logout", null, null, ClientIp, ClientUa, ct);

        return Ok(new { message = "Logged out successfully" });
    }

    // POST /api/auth/logout-all  (revoke all sessions)
    [HttpPost("logout-all")]
    [Authorize]
    public async Task<IActionResult> LogoutAll(CancellationToken ct)
    {
        var userId      = GetCurrentUserId();
        var accessToken = GetBearerToken();
        if (accessToken is not null)
            await tokens.BlacklistAccessTokenAsync(accessToken, ct);

        await tokens.RevokeAllUserTokensAsync(userId, ct);
        await audit.LogAsync(userId, "logout.all", null, null, ClientIp, ClientUa, ct);
        return Ok(new { message = "All sessions revoked" });
    }

    // GET /api/auth/me
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType<UserDto>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        var user   = await users.GetByIdAsync(userId, ct);
        return user is null ? NotFound() : Ok(user.ToDto());
    }

    // GET /api/auth/verify?token=...  — for service-to-service validation
    [HttpGet("verify")]
    [ProducesResponseType<TokenValidationResponse>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Verify([FromQuery] string token, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token))
            return Ok(new TokenValidationResponse(false, Error: "Token is required"));

        if (await tokens.IsAccessTokenBlacklistedAsync(token, ct))
            return Ok(new TokenValidationResponse(false, Error: "Token has been revoked"));

        var payload = tokens.ValidateAccessToken(token);
        if (payload is null)
            return Ok(new TokenValidationResponse(false, Error: "Invalid or expired token"));

        return Ok(new TokenValidationResponse(true, new UserDto(
            payload.UserId, payload.Username, payload.Email,
            payload.DisplayName, payload.Role, true, false, null, DateTime.MinValue)));
    }

    // POST /api/auth/change-password
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req, CancellationToken ct)
    {
        var userId  = GetCurrentUserId();
        var changed = await users.ChangePasswordAsync(userId, req.CurrentPassword, req.NewPassword, ct);
        if (!changed) return BadRequest(new { error = "Current password is incorrect" });

        await tokens.RevokeAllUserTokensAsync(userId, ct);
        await audit.LogAsync(userId, "password.changed", null, null, ClientIp, ClientUa, ct);
        return Ok(new { message = "Password changed. Please login again." });
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private int GetCurrentUserId() =>
        int.TryParse(User.FindFirst("uid")?.Value, out var id) ? id : 0;

    private string? GetBearerToken()
    {
        var auth = Request.Headers.Authorization.ToString();
        return auth.StartsWith("Bearer ") ? auth["Bearer ".Length..] : null;
    }

    private string IssueTempToken(int userId)
    {
        // Short-lived temp token for MFA flow (not full access)
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"mfa:{userId}:{DateTime.UtcNow.AddMinutes(5):O}"));
    }
}
