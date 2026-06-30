namespace CentralAuth.Models;

public class LoginVm
{
    public string Login       { get; set; } = "";   // username หรือ email
    public string Password    { get; set; } = "";
    public bool   Remember    { get; set; }
    public string AppId       { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public string? Error      { get; set; }
}

public class CentralUser
{
    public int     Id           { get; set; }
    public string  Username     { get; set; } = "";
    public string? Email        { get; set; }
    public string  PasswordHash { get; set; } = "";
    public string? DisplayName  { get; set; }
    public string  Role         { get; set; } = "user";
    public bool    IsActive     { get; set; }
    public bool    MfaEnabled   { get; set; }
}

public class TokenPayload
{
    public int    UserId      { get; set; }
    public string Username    { get; set; } = "";
    public string Email       { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Role        { get; set; } = "";
    public string AppId       { get; set; } = "";
}
