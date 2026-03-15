// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress;
using Cratis.Ingress.Configuration;
using Cratis.Ingress.Identity;
using Cratis.Ingress.Invites;
using Cratis.Ingress.ReverseProxy;
using Cratis.Ingress.Tenancy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

// ── Configuration ──────────────────────────────────────────────────────────
builder.Services
    .AddOptions<IngressConfig>()
    .BindConfiguration("Ingress")
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<AuthenticationConfig>()
    .BindConfiguration("Authentication")
    .ValidateDataAnnotations()
    .ValidateOnStart();

// ── Authentication ─────────────────────────────────────────────────────────
// The ingress supports two authentication flows:
//   • Interactive browser sessions via OIDC + cookie (default for frontends).
//   • Machine-to-machine / API via JWT Bearer.
// Both can be active simultaneously; the middleware challenges with OIDC for
// browser requests and with Bearer for API calls.
var authBuilder = builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

        // Redirect unauthenticated users to either the provider selection page
        // (multiple providers) or directly to the single provider login endpoint.
        options.Events.OnRedirectToLogin = ctx =>
        {
            var authConfig = ctx.HttpContext.RequestServices
                .GetRequiredService<IOptionsMonitor<AuthenticationConfig>>()
                .CurrentValue;

            var returnUrl = ctx.Request.Path + ctx.Request.QueryString;

            if (authConfig.OidcProviders.Count > 1)
            {
                ctx.Response.Redirect($"{WellKnownPaths.LoginPage}?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return Task.CompletedTask;
            }

            if (authConfig.OidcProviders.Count == 1)
            {
                var schemeName = OidcProviderScheme.FromName(authConfig.OidcProviders[0].Name);
                ctx.Response.Redirect($"{WellKnownPaths.LoginPrefix}/{schemeName}?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return Task.CompletedTask;
            }

            ctx.Response.Redirect(ctx.RedirectUri);
            return Task.CompletedTask;
        };
    });

// ── OIDC providers (Authentication:OidcProviders) ──────────────────────────
// Each provider is registered as its own OIDC scheme so that the ingress can
// challenge with the correct one based on the provider the user selected.
var oidcProviders = builder.Configuration
    .GetSection("Authentication:OidcProviders")
    .Get<List<OidcProviderConfig>>() ?? [];

foreach (var provider in oidcProviders)
{
    var schemeName = OidcProviderScheme.FromName(provider.Name);
    authBuilder.AddOpenIdConnect(schemeName, options =>
    {
        options.Authority = provider.Authority;
        options.ClientId = provider.ClientId;
        options.ClientSecret = provider.ClientSecret;
        options.ResponseType = "code";
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        foreach (var scope in provider.Scopes)
        {
            options.Scope.Add(scope);
        }

        options.CallbackPath = $"/signin-{schemeName}";
    });
}

var jwtSection = builder.Configuration.GetSection("Authentication:JwtBearer");
if (jwtSection.Exists())
{
    authBuilder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        jwtSection.Bind(options);
    });
}

builder.Services.AddAuthorization(options =>
{
    // Set the default policy to require an authenticated user.
    // Note: do not use AddPolicy("default", ...) – YARP reserves that name internally.
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// ── Tenancy ────────────────────────────────────────────────────────────────
builder.Services.AddSingleton<ISourceIdentifierStrategy, HostSourceIdentifierStrategy>();
builder.Services.AddSingleton<ISourceIdentifierStrategy, ClaimSourceIdentifierStrategy>();
builder.Services.AddSingleton<ISourceIdentifierStrategy, RouteSourceIdentifierStrategy>();
builder.Services.AddSingleton<ISourceIdentifierStrategy, SpecifiedSourceIdentifierStrategy>();
builder.Services.AddSingleton<ITenantResolver, TenantResolver>();

// ── Identity ───────────────────────────────────────────────────────────────
builder.Services.AddHttpClient();
builder.Services.AddSingleton<IIdentityDetailsResolver, IdentityDetailsResolver>();

// ── Invites ────────────────────────────────────────────────────────────────
builder.Services.AddSingleton<IInviteTokenValidator, InviteTokenValidator>();

// ── Reverse proxy ──────────────────────────────────────────────────────────
builder.SetupReverseProxy();

// ── Forwarded headers (when running behind a load-balancer / nginx) ────────
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

// ── Application ────────────────────────────────────────────────────────────
var app = builder.Build();

app.UseForwardedHeaders();

// Serve the bundled Web SPA assets (wwwroot) so the login selection page is available.
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// TenancyMiddleware strips spoofable inbound headers, resolves the tenant and
// calls /.cratis/me to enrich the identity cookie – runs after auth so the
// ClaimsPrincipal is available. Tenancy must be resolved before the invite
// system so the lobby redirect can be applied when no tenant is found.
app.UseMiddleware<TenancyMiddleware>();

// InviteMiddleware handles the /invite/{token} path and exchanges pending invite
// tokens with Studio after a successful OIDC login.
app.UseMiddleware<InviteMiddleware>();

// ── OIDC providers endpoint ────────────────────────────────────────────────
// Returns a JSON array of OidcProviderInfo objects that the login page uses to
// render the list of available login options.
app.MapGet(WellKnownPaths.Providers, (IOptionsMonitor<AuthenticationConfig> config) =>
{
    var providers = config.CurrentValue.OidcProviders;
    var result = providers.Select(OidcProviderScheme.ToProviderInfo);

    return Results.Json(result);
});

// ── Per-provider login endpoints ───────────────────────────────────────────
// Initiates the OIDC challenge for the requested provider scheme.
app.MapGet($"{WellKnownPaths.LoginPrefix}/{{scheme}}", async (string scheme, HttpContext context) =>
{
    var returnUrl = context.Request.Query["returnUrl"].FirstOrDefault() ?? "/";
    var properties = new AuthenticationProperties { RedirectUri = returnUrl };
    await context.ChallengeAsync(scheme, properties);
});

// ── Login selection page (SPA fallback) ───────────────────────────────────
// Serves the bundled React app for any request under /.cratis/select-provider.
app.MapGet($"{WellKnownPaths.LoginPage}/{{**path}}", async (HttpContext context) =>
{
    context.Response.ContentType = "text/html";
    await context.Response.SendFileAsync(
        Path.Combine(app.Environment.WebRootPath, "index.html"));
});

app.UseReverseProxy();

await app.RunAsync();
