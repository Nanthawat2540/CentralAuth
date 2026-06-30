using CentralAuth.Models;
using CentralAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CentralAuth.Controllers.Api;

[ApiController]
[Route("api/users")]
[Authorize]
[Produces("application/json")]
public class ApiUsersController(IUserService users, IAuditService audit) : ControllerBase
{
    private string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();
    private string? ClientUa => Request.Headers.UserAgent.ToString();
    private int     UserId   => int.TryParse(User.FindFirst("uid")?.Value, out var id) ? id : 0;
    private bool    IsAdmin  => User.FindFirst("role")?.Value == "admin";

    // GET /api/users?page=1&pageSize=20&search=...
    [HttpGet]
    [ProducesResponseType<PagedResult<UserDto>>(StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAll(
        [FromQuery] int    page     = 1,
        [FromQuery] int    pageSize = 20,
        [FromQuery] string? search  = null,
        CancellationToken ct = default)
    {
        if (!IsAdmin) return Forbid();
        if (page < 1) page = 1;
        if (pageSize is < 1 or > 100) pageSize = 20;

        var result = await users.GetUsersAsync(page, pageSize, search, ct);
        return Ok(result);
    }

    // GET /api/users/{id}
    [HttpGet("{id:int}")]
    [ProducesResponseType<UserDto>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetById(int id, CancellationToken ct)
    {
        // Users can only see themselves, admins can see anyone
        if (!IsAdmin && UserId != id) return Forbid();

        var user = await users.GetByIdAsync(id, ct);
        return user is null ? NotFound() : Ok(user.ToDto());
    }

    // POST /api/users  (admin only)
    [HttpPost]
    [ProducesResponseType<UserDto>(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Create([FromBody] CreateUserRequest req, CancellationToken ct)
    {
        if (!IsAdmin) return Forbid();
        if (await users.UsernameExistsAsync(req.Username, ct))
            return Conflict(new { error = "Username already taken" });
        if (await users.EmailExistsAsync(req.Email, ct))
            return Conflict(new { error = "Email already registered" });

        var userDto = await users.CreateAsync(req, ct);
        await audit.LogAsync(UserId, "user.created", $"users/{userDto.Id}", new { username = req.Username }, ClientIp, ClientUa, ct);
        return Created($"/api/users/{userDto.Id}", userDto);
    }

    // PUT /api/users/{id}
    [HttpPut("{id:int}")]
    [ProducesResponseType<UserDto>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateUserRequest req, CancellationToken ct)
    {
        // Non-admins can only update themselves, and can't change role
        if (!IsAdmin)
        {
            if (UserId != id) return Forbid();
            req = req with { Role = null, IsActive = null };
        }

        var updated = await users.UpdateAsync(id, req, ct);
        if (updated is null) return NotFound();

        await audit.LogAsync(UserId, "user.updated", $"users/{id}", null, ClientIp, ClientUa, ct);
        return Ok(updated);
    }

    // DELETE /api/users/{id}  (admin only — soft delete)
    [HttpDelete("{id:int}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        if (!IsAdmin) return Forbid();
        if (id == UserId) return BadRequest(new { error = "Cannot delete yourself" });

        var deleted = await users.DeleteAsync(id, ct);
        if (!deleted) return NotFound();

        await audit.LogAsync(UserId, "user.deleted", $"users/{id}", null, ClientIp, ClientUa, ct);
        return Ok(new { message = "User deactivated" });
    }
}
