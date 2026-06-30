using System.Text;
using CentralAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using Serilog;

// ── Serilog Bootstrap ────────────────────────────────────────────────────
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // ── Serilog ──────────────────────────────────────────────────────────
    builder.Host.UseSerilog((ctx, cfg) => cfg
        .ReadFrom.Configuration(ctx.Configuration)
        .Enrich.FromLogContext()
        .Enrich.WithMachineName()
        .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
        .WriteTo.File("logs/centralauth-.log", rollingInterval: RollingInterval.Day, retainedFileCountLimit: 30));

    var services = builder.Services;
    var config   = builder.Configuration;

    // ── MVC (existing SSO web pages) ─────────────────────────────────────
    services.AddControllersWithViews();

    // ── OpenAPI ──────────────────────────────────────────────────────────
    services.AddOpenApi("v1", opt =>
    {
        opt.AddDocumentTransformer((doc, ctx, ct) =>
        {
            doc.Info.Title       = "PasTechs CentralAuth API";
            doc.Info.Version     = "v1";
            doc.Info.Description = "Central Authentication & Authorization Service — shared across all PasTechs projects";
            return Task.CompletedTask;
        });
    });

    // ── Infrastructure ───────────────────────────────────────────────────
    services.AddSingleton<IDbConnectionFactory, SqlConnectionFactory>();

    // ── Application Services ─────────────────────────────────────────────
    services.AddScoped<IAuthService,   AuthService>();
    services.AddScoped<ITokenService,  TokenService>();
    services.AddScoped<IUserService,   UserService>();
    services.AddScoped<IApiKeyService, ApiKeyService>();
    services.AddScoped<IAuditService,  AuditService>();

    // ── Redis / Distributed Cache ─────────────────────────────────────────
    var redisConn = config["Redis:ConnectionString"];
    if (!string.IsNullOrEmpty(redisConn))
        services.AddStackExchangeRedisCache(opt => opt.Configuration = redisConn);
    else
    {
        services.AddDistributedMemoryCache();
        Log.Warning("Redis not configured — using in-memory cache (single-instance only)");
    }

    // ── JWT Authentication ────────────────────────────────────────────────
    var jwtSecret = config["Jwt:Secret"] ?? throw new InvalidOperationException("Jwt:Secret is required");
    services.AddAuthentication(opt =>
    {
        opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        opt.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer   = true,
            ValidIssuer      = "central-auth",
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ClockSkew        = TimeSpan.Zero,
        };
        opt.Events = new JwtBearerEvents
        {
            OnTokenValidated = async ctx =>
            {
                var tokenSvc = ctx.HttpContext.RequestServices.GetRequiredService<ITokenService>();
                var auth     = ctx.HttpContext.Request.Headers.Authorization.ToString();
                var token    = auth.StartsWith("Bearer ") ? auth["Bearer ".Length..] : "";
                if (!string.IsNullOrEmpty(token) && await tokenSvc.IsAccessTokenBlacklistedAsync(token))
                    ctx.Fail("Token has been revoked");
            }
        };
    })
    .AddGoogle(opt =>
    {
        opt.ClientId     = config["OAuth:Google:ClientId"]     ?? "";
        opt.ClientSecret = config["OAuth:Google:ClientSecret"] ?? "";
    })
    .AddMicrosoftAccount(opt =>
    {
        opt.ClientId     = config["OAuth:Microsoft:ClientId"]     ?? "";
        opt.ClientSecret = config["OAuth:Microsoft:ClientSecret"] ?? "";
    });

    services.AddAuthorization();

    // ── CORS ──────────────────────────────────────────────────────────────
    var allowedOrigins = (config["Auth:AllowedOrigins"] ?? config["Auth:AllowedHosts"] ?? "localhost")
        .Split(',', StringSplitOptions.TrimEntries)
        .SelectMany(h => new[] { $"https://{h}", $"http://{h}" })
        .Concat(["http://localhost:3000", "http://localhost:5173", "http://localhost:4173"])
        .Distinct().ToArray();

    services.AddCors(opt => opt.AddPolicy("AllApps", p => p
        .WithOrigins(allowedOrigins)
        .AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

    // ── Health Checks ────────────────────────────────────────────────────
    var hc = services.AddHealthChecks()
        .AddSqlServer(config.GetConnectionString("CentralAuth") ?? "", name: "sqlserver");
    if (!string.IsNullOrEmpty(redisConn))
        hc.AddRedis(redisConn, name: "redis");

    // ── Build ─────────────────────────────────────────────────────────────
    var app = builder.Build();

    app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
        KnownNetworks    = { },
        KnownProxies     = { }
    });

    app.UseSerilogRequestLogging(opt =>
        opt.MessageTemplate = "HTTP {RequestMethod} {RequestPath} {StatusCode} in {Elapsed:0.0}ms");

    app.UseCors("AllApps");
    app.UseStaticFiles();
    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();

    // OpenAPI + Scalar UI at /scalar/v1
    app.MapOpenApi();
    app.MapScalarApiReference(opt =>
    {
        opt.Title             = "CentralAuth API";
        opt.Theme             = ScalarTheme.Purple;
        opt.DefaultHttpClient = new(ScalarTarget.CSharp, ScalarClient.HttpClient);
    });

    // Health endpoint
    app.MapHealthChecks("/health");

    // REST API controllers
    app.MapControllers();

    // SSO Web routes (backward compat — keep exactly as before)
    app.MapControllerRoute("default", "{controller=Auth}/{action=Login}/{id?}");
    app.MapGet("/", ctx => { ctx.Response.Redirect("/auth/login"); return Task.CompletedTask; });

    Log.Information("CentralAuth v2 starting [{Env}]", app.Environment.EnvironmentName);
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "CentralAuth failed to start");
    throw;
}
finally
{
    Log.CloseAndFlush();
}
