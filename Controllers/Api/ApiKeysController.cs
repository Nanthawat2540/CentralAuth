using CentralAuth.Models;
using CentralAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CentralAuth.Controllers.Api;

[ApiController]
[Route("api/apikeys")]
[Authorize]
[Produces("application/json")]
public class ApiKeysController(IApiKeyService apiKeys, IAuditService audit) : ControllerBase
{
    private int     UserId  => int.TryParse(User.FindFirst("uid")?.Value, out var id) ? id : 0;
    private bool    IsAdmin => User.FindFirst("role")?.Value == "admin";
    private string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();
    private string? ClientUa => Request.Headers.UserAgent.ToString();

    // GET /api/apikeys
    [HttpGet]
    [ProducesResponseType<List<ApiKeyResponse>>(StatusCodes.Status200OK)]
    public async Task<IActionResult> GetMine(CancellationToken ct)
    {
        var keys = await apiKeys.GetByUserAsync(UserId, ct);
        return Ok(keys);
    }

    // POST /api/apikeys
    [HttpPost]
    [ProducesResponseType<ApiKeyResponse>(StatusCodes.Status201Created)]
    public async Task<IActionResult> Create([FromBody] CreateApiKeyRequest req, CancellationToken ct)
    {
        var (response, _) = await apiKeys.CreateAsync(req, UserId, ct);
        await audit.LogAsync(UserId, "apikey.created", $"apikeys/{response.Id}", new { name = req.Name }, ClientIp, ClientUa, ct);
        return Created($"/api/apikeys/{response.Id}", response);
    }

    // DELETE /api/apikeys/{id}
    [HttpDelete("{id:int}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Revoke(int id, CancellationToken ct)
    {
        // Admins can revoke any key; users can only revoke their own
        var ownerId = IsAdmin ? (int?)null : UserId;
        var ok      = await apiKeys.RevokeAsync(id, ownerId, ct);
        if (!ok) return NotFound();

        await audit.LogAsync(UserId, "apikey.revoked", $"apikeys/{id}", null, ClientIp, ClientUa, ct);
        return Ok(new { message = "API key revoked" });
    }

    // POST /api/apikeys/validate  — for services to validate API keys
    [HttpPost("validate")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Validate([FromBody] string rawKey, CancellationToken ct)
    {
        var key = await apiKeys.ValidateAsync(rawKey, ct);
        if (key is null) return Ok(new { valid = false });
        return Ok(new { valid = true, keyId = key.Id, userId = key.UserId, appId = key.AppId });
    }
}
