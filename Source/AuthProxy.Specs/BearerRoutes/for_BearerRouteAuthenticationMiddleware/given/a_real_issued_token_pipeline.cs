// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteAuthenticationMiddleware.given;

public abstract class a_real_issued_token_pipeline : Specification
{
    protected const string Metadata = "https://portal.test/.well-known/oauth-protected-resource/api";
    protected ServiceProvider Services = default!;
    protected RequestDelegate Pipeline = default!;
    protected C.AuthProxy Config = default!;
    protected IBearerTokenValidator Validator = default!;
    protected IBearerRouteForwarder Forwarder = default!;
    protected Action<HttpContext> BetweenGateAndAuthentication = _ => { };
    protected int CookieValidations;
    protected int JwtAuthentications;
    protected int DownstreamCalls;
    protected string Token = string.Empty;
    protected string BrowserCookie = string.Empty;
    protected readonly controllable_clock Clock = new();

    protected async Task<DefaultHttpContext> Send(string path = "/api/x", bool cookie = false, string? token = null, string host = "portal.test", string? tenant = null)
    {
        await using var scope = Services.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = path;
        context.Request.Host = new HostString(host);
        context.Response.Body = new MemoryStream();
        if (token is not null) context.Request.Headers.Authorization = $"Bearer {token}";
        if (cookie) context.Request.Headers.Cookie = BrowserCookie;
        if (tenant is not null) context.Request.Headers[Headers.TenantId] = tenant;
        await Pipeline(context);
        return context;
    }

    protected void AcceptPersonalAccessTokensOnly()
    {
        var route = Config.Services["portal"].BearerRoutes[0];
        route.PersonalAccessTokens = new() { ResourceKey = "direct" };
        route.Issuers = [];
        route.Audiences = [];
        route.ResourceMetadataUrl = string.Empty;
    }

    void Establish()
    {
        Config = new()
        {
            TenantResolutions = [new() { Strategy = C.TenantSourceIdentifierResolverType.Host }],
            Services = new Dictionary<string, C.Service>
            {
                ["portal"] = new()
                {
                    Hosts = ["portal.test"],
                    Backend = new() { BaseUrl = "https://portal.test" },
                    ClientCredentials = new() { RoutePrefix = "/api", VerificationPath = "/verify" },
                    BearerRoutes =
                    [
                        new()
                        {
                            PathPrefix = "/api",
                            Issuers = [new() { Issuer = "https://issuer.test" }],
                            Audiences = ["portal-api"],
                            ResourceMetadataUrl = Metadata,
                        },
                    ],
                },
                ["catalog"] = new() { Hosts = ["catalog.test"], Backend = new() { BaseUrl = "https://catalog.test" } },
            },
        };
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(Config);
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        builder.Services.AddSingleton<TimeProvider>(Clock);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:JwtBearer:Instance"] = "https://login.microsoftonline.com/",
            [$"{C.Authentication.SectionKey}:JwtBearer:TenantId"] = "00000000-0000-0000-0000-000000000001",
            [$"{C.Authentication.SectionKey}:JwtBearer:ClientId"] = "00000000-0000-0000-0000-000000000002",
        });
        builder.AddIngressAuthentication();
        builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
        {
            options.Events = new()
            {
                OnMessageReceived = context =>
                {
                    JwtAuthentications++;
                    context.Fail("The generic JWT handler must not authenticate a bearer-route request.");
                    return Task.CompletedTask;
                },
            };
        });
        builder.Services.Configure<AuthenticationSchemeOptions>(ClientCredentialsDefaults.AuthenticationScheme, options => options.TimeProvider = Clock);
        builder.Services.PostConfigure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.TimeProvider = Clock;
            options.Events = new()
            {
                OnValidatePrincipal = _ =>
                {
                    CookieValidations++;
                    return Task.CompletedTask;
                },
            };
        });

        Validator = Substitute.For<IBearerTokenValidator>();
        Forwarder = Substitute.For<IBearerRouteForwarder>();
        builder.Services.AddSingleton(Validator);
        builder.Services.AddSingleton(Forwarder);
        var policy = Substitute.For<IAccessPolicy>();
        policy.Evaluate(Arg.Any<ClaimsPrincipal>(), Arg.Any<C.AuthProxy>(), Arg.Any<string>(), Arg.Any<C.BearerRoute>()).Returns(AccessDecision.Granted);
        builder.Services.AddSingleton(policy);
        var verifier = Substitute.For<ITenantVerifier>();
        verifier.VerifyAsync(Arg.Any<string>()).Returns(true);
        builder.Services.AddSingleton(verifier);
        var resolver = Substitute.For<ITenantResolver>();
        resolver.ResolveEach(Arg.Any<HttpContext>()).Returns(call =>
        {
            var tenant = call.Arg<HttpContext>().Request.Headers[Headers.TenantId].ToString();
            return tenant.Length == 0 ? [] : new TenantResolutionResult[] { new(tenant, C.TenantSourceIdentifierResolverType.Host) };
        });
        builder.Services.AddSingleton(resolver);
        builder.Services.AddSingleton<SelectedTenantCookie>();
        var pages = Substitute.For<IErrorPageProvider>();
        pages.WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>()).Returns(call =>
        {
            call.Arg<HttpContext>().Response.StatusCode = call.Arg<int>();
            return Task.CompletedTask;
        });
        builder.Services.AddSingleton(pages);
        Services = builder.Services.BuildServiceProvider();

        var protector = Services.GetRequiredService<ClientCredentialsTokenProtector>();
        Token = protector.CreateToken(new("portal", "/api", new Uri("https://portal.test/verify")), "machine", "tenant-a");
        var cookies = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "browser"), new Claim(ClientCredentialsDefaults.TenantClaimType, "tenant-b")], CookieAuthenticationDefaults.AuthenticationScheme));
        var ticket = new AuthenticationTicket(principal, new() { IssuedUtc = Clock.GetUtcNow(), ExpiresUtc = Clock.GetUtcNow().AddDays(1) }, CookieAuthenticationDefaults.AuthenticationScheme);
        BrowserCookie = $"{cookies.Cookie.Name}={cookies.TicketDataFormat.Protect(ticket)}";

        var app = new ApplicationBuilder(Services);
        app.UseMiddleware<BearerRouteMiddleware>();
        app.Use((context, next) =>
        {
            BetweenGateAndAuthentication(context);
            return next(context);
        });
        app.UseAuthentication();
        app.UseMiddleware<BearerRouteAuthenticationMiddleware>();
        app.UseMiddleware<CredentialBindingMiddleware>();
        app.Run(context =>
        {
            DownstreamCalls++;
            return context.Response.WriteAsync("backend");
        });
        Pipeline = app.Build();
    }

    async Task Destroy() => await Services.DisposeAsync();

    protected sealed class controllable_clock : TimeProvider
    {
        DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;

        internal void ExpireAccessToken() => _now = _now.AddHours(2);
    }
}
