using CentralAuth.Models;
using CentralAuth.Services;
using Microsoft.AspNetCore.Mvc;

namespace CentralAuth.Controllers;

public class AuthController(IAuthService authSvc, IConfiguration config) : Controller
{
    // allowed redirect hosts (whitelist)
    private readonly HashSet<string> _allowedHosts = (
        config["Auth:AllowedHosts"] ?? "localhost")
        .Split(',', StringSplitOptions.TrimEntries)
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

    // GET /auth/login?app_id=billing&redirect_uri=https://billing.pastechs.com/auth/callback
    [HttpGet("/auth/login")]
    public IActionResult Login(string? app_id, string? redirect_uri)
    {
        return View(new LoginVm
        {
            AppId       = app_id       ?? "",
            RedirectUri = redirect_uri ?? "",
        });
    }

    // POST /auth/login
    [HttpPost("/auth/login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginVm vm)
    {
        if (string.IsNullOrWhiteSpace(vm.Login) || string.IsNullOrWhiteSpace(vm.Password))
        {
            vm.Error = "กรุณากรอก Username และ Password";
            return View(vm);
        }

        var user = await authSvc.ValidateAsync(vm.Login, vm.Password);
        if (user is null)
        {
            vm.Error = "Username/Password ไม่ถูกต้อง";
            return View(vm);
        }

        var token = authSvc.IssueToken(user, vm.AppId);

        // ถ้ามี redirect_uri ที่อนุญาต → ส่งกลับพร้อม token
        if (!string.IsNullOrEmpty(vm.RedirectUri)
            && Uri.TryCreate(vm.RedirectUri, UriKind.Absolute, out var uri)
            && IsAllowedHost(uri.Host))
        {
            var callbackUrl = $"{vm.RedirectUri}?token={Uri.EscapeDataString(token)}";
            return Redirect(callbackUrl);
        }

        // ไม่มี redirect_uri → ไปหน้าเลือก app
        return Redirect($"/auth/select?token={Uri.EscapeDataString(token)}");
    }

    // GET /auth/select?token=...  (หน้าเลือก app หลัง login)
    [HttpGet("/auth/select")]
    public IActionResult Select(string? token)
    {
        if (string.IsNullOrEmpty(token)) return Redirect("/auth/login");
        var payload = authSvc.VerifyToken(token);
        if (payload is null) return Redirect("/auth/login");
        ViewBag.Token       = token;
        ViewBag.DisplayName = payload.DisplayName ?? payload.Username;
        return View();
    }

    // GET /auth/verify?token=...  (สำหรับ app อื่นเรียก verify)
    [HttpGet("/auth/verify")]
    public IActionResult Verify([FromQuery] string token)
    {
        var payload = authSvc.VerifyToken(token);
        if (payload is null) return Unauthorized(new { valid = false });
        return Ok(new { valid = true, user = payload });
    }

    // GET /auth/logout?redirect_uri=...
    [HttpGet("/auth/logout")]
    public IActionResult Logout(string? redirect_uri)
    {
        if (!string.IsNullOrEmpty(redirect_uri)
            && Uri.TryCreate(redirect_uri, UriKind.Absolute, out var uri)
            && IsAllowedHost(uri.Host))
            return Redirect(redirect_uri);

        return Ok(new { message = "logged out" });
    }

    private bool IsAllowedHost(string host) =>
        _allowedHosts.Any(h => host.Equals(h, StringComparison.OrdinalIgnoreCase)
                            || host.EndsWith("." + h, StringComparison.OrdinalIgnoreCase));
}
