namespace CentralAuth.Models;

// ── Core Entities ─────────────────────────────────────────────────────────

public class User
{
    public int      Id           { get; set; }
    public string   Username     { get; set; } = "";
    public string?  Email        { get; set; }
    public string   PasswordHash { get; set; } = "";
    public string?  DisplayName  { get; set; }
    public string   Role         { get; set; } = "user";
    public bool     IsActive     { get; set; }
    public bool     MfaEnabled   { get; set; }
    public string?  MfaSecret    { get; set; }
    public DateTime? LastLogin   { get; set; }
    public DateTime CreatedAt    { get; set; }
    public DateTime UpdatedAt    { get; set; }
}

public class RefreshToken
{
    public long     Id          { get; set; }
    public int      UserId      { get; set; }
    public string   Token       { get; set; } = "";
    public DateTime ExpiresAt   { get; set; }
    public DateTime? RevokedAt  { get; set; }
    public string?  ReplacedBy  { get; set; }
    public string?  IpAddress   { get; set; }
    public string?  UserAgent   { get; set; }
    public DateTime CreatedAt   { get; set; }
    public bool     IsExpired   => DateTime.UtcNow >= ExpiresAt;
    public bool     IsRevoked   => RevokedAt != null;
    public bool     IsActive    => !IsRevoked && !IsExpired;
}

public class Permission
{
    public int     Id          { get; set; }
    public string  Name        { get; set; } = "";   // e.g. "users.read"
    public string  Module      { get; set; } = "";   // e.g. "users"
    public string  Action      { get; set; } = "";   // e.g. "read"
    public string? Description { get; set; }
}

public class ApiKey
{
    public int      Id          { get; set; }
    public string   KeyHash     { get; set; } = "";
    public string   Name        { get; set; } = "";
    public int?     UserId      { get; set; }
    public string?  AppId       { get; set; }
    public string?  Permissions { get; set; }  // JSON array
    public DateTime? ExpiresAt  { get; set; }
    public DateTime? LastUsed   { get; set; }
    public bool     IsActive    { get; set; } = true;
    public DateTime CreatedAt   { get; set; }
}

public class AuditLog
{
    public long     Id         { get; set; }
    public int?     UserId     { get; set; }
    public string   Action     { get; set; } = "";
    public string?  Resource   { get; set; }
    public string?  Details    { get; set; }
    public string?  IpAddress  { get; set; }
    public string?  UserAgent  { get; set; }
    public DateTime CreatedAt  { get; set; }
}

// LoginVm, CentralUser, TokenPayload are defined in AuthModels.cs (existing file)
