using CentralAuth.Services;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
    KnownNetworks = { },
    KnownProxies  = { }
});

app.UseStaticFiles();
app.UseRouting();

app.MapControllerRoute("default", "{controller=Auth}/{action=Login}/{id?}");
app.MapGet("/", context => { context.Response.Redirect("/auth/login"); return Task.CompletedTask; });

app.Run();
