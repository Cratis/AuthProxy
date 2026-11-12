// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Cratis.AuthProxy.AccessTokens;
using Cratis.AuthProxy.ForwardedIdentity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A signed service using real cookie tickets and the completed provider sign-in events.</summary>
/// <param name="enabled">Whether this service opts in to session-context forwarding.</param>
public class SessionContextHarness(bool enabled = true) : ForwardedIdentityHarness
{
    public const string Path = "/signed-a";
    public new const string Audience = "signed-backend";
    public const string KeyId = "active-1";
    public static readonly byte[] Key = Enumerable.Repeat((byte)42, 32).ToArray();
    public int Refreshes { get; private set; }
    public FakeTimeProvider Clock { get; } = new(DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
    protected override bool UsesHeaderAuthentication => false;

    public async Task<string> SignIn(bool oidc = true, string? hostileClaim = null, string? tokenSession = null)
    {
        var scheme = oidc ? "provider-one" : "github";
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "session-user"), new Claim("email", "user@example.test")], "AuthenticationTypes.Federation"));
        if (hostileClaim is not null) ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(hostileClaim, "caller-forged"));
        var properties = new AuthenticationProperties { IssuedUtc = Clock.GetUtcNow(), ExpiresUtc = Clock.GetUtcNow().AddHours(1) };
        var context = new DefaultHttpContext { RequestServices = Services };
        context.Request.Scheme = "https";
        RemoteAuthenticationOptions providerOptions = oidc
            ? Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(scheme)
            : Services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get(scheme);
        var ticket = new TicketReceivedContext(context, new AuthenticationScheme(scheme, scheme, oidc ? typeof(OpenIdConnectHandler) : typeof(OAuthHandler<OAuthOptions>)), providerOptions, new AuthenticationTicket(principal, properties, scheme));
        if (providerOptions is OpenIdConnectOptions oidcOptions) await oidcOptions.Events.OnTicketReceived(ticket);
        else await ((OAuthOptions)providerOptions).Events.OnTicketReceived(ticket);
        if (tokenSession is not null) properties.Items[UserTokenSessions.PropertiesKey] = tokenSession;
        var options = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");
        options.CookieManager.AppendResponseCookie(context, options.Cookie.Name!, options.TicketDataFormat.Protect(new AuthenticationTicket(ticket.Principal!, properties, "Cookies")), options.Cookie.Build(context));
        return string.Join("; ", context.Response.Headers.SetCookie.Select(cookie => cookie!.Split(';', 2)[0]));
    }

    public static HttpRequestMessage Request(string cookie)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, Path);
        request.Headers.Host = SignedHost;
        request.Headers.Add("Cookie", cookie);
        return request;
    }

    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        const string service = $"{C.AuthProxy.SectionKey}:Services:app";
        settings[$"{service}:ResolveIdentityDetails"] = "false";
        settings[$"{service}:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort);
        if (enabled) settings[$"{service}:ForwardSessionContext"] = "true";
        settings[$"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret"] = "spec-client-secret";
        settings[$"{C.Session.SectionKey}:Lifetime"] = "01:00:00";
        settings[$"{C.Session.SectionKey}:SlidingExpiration"] = "true";
        settings[$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = "GitHub";
        settings[$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "https://github.example.test/authorize";
        settings[$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "https://github.example.test/token";
        settings[$"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint"] = "https://github.example.test/user";
        settings[$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "github-client";
    }

    public ForwardedRequest Observed()
    {
        var observation = ApplicationOrigin.Received.Last(request => request.RawTarget == "/base" + Path);
        return new ForwardedRequest(observation.Method, observation.RawTarget, string.Empty, observation.Headers.ToDictionary(header => header.Key, header => header.Value.Single(), StringComparer.OrdinalIgnoreCase));
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Provider registration reads configuration while Program builds the authentication handlers.
        builder
            .UseSetting($"{C.Authentication.SectionKey}:OidcProviders:0:Name", "Provider One")
            .UseSetting($"{C.Authentication.SectionKey}:OidcProviders:0:Authority", "https://login.example.test/one")
            .UseSetting($"{C.Authentication.SectionKey}:OidcProviders:0:ClientId", "client-one")
            .UseSetting($"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret", "spec-client-secret")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:Name", "GitHub")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId", "github-client")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret", "spec-client-secret")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint", "https://github.example.test/authorize")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint", "https://github.example.test/token")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint", "https://github.example.test/user")
            .UseSetting($"{C.Session.SectionKey}:Lifetime", "01:00:00")
            .UseSetting($"{C.Session.SectionKey}:SlidingExpiration", "true");
        base.ConfigureWebHost(builder);
    }

    protected override void ConfigureHost(IWebHostBuilder builder)
    {
        base.ConfigureHost(builder);
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<TimeProvider>(Clock);

            // Advancing session time must not expire the proof against the independent origin's wall clock.
            services.AddSingleton<IForwardedIdentitySigner>(provider => new ForwardedIdentitySigner(provider.GetRequiredService<IOptionsMonitor<C.AuthProxy>>(), TimeProvider.System, provider.GetRequiredService<ILogger<ForwardedIdentitySigner>>()));
            services.PostConfigure<CookieAuthenticationOptions>("Cookies", options => options.TimeProvider = Clock);
            services.PostConfigure<OpenIdConnectOptions>("provider-one", options => options.Configuration = new OpenIdConnectConfiguration { TokenEndpoint = "https://login.example.test/token" });
            services.AddHttpClient(UserAccessTokens.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => new RefreshEndpoint(this));
        });
    }

    sealed class RefreshEndpoint(SessionContextHarness harness) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            harness.Refreshes++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"refreshed-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}", System.Text.Encoding.UTF8, "application/json") });
        }
    }
}
