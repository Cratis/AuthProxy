// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The running proxy with one real OAuth provider and one real OpenID Connect provider, each driven through the
/// whole challenge, provider callback and cookie sign-in so a spec can read the properties of the ticket the
/// session cookie holds.
/// </summary>
/// <remarks>
/// Only the identity provider's own endpoints are stood in for. The remote handlers, their state protection, the
/// ticket-received handling and the cookie scheme are the production ones.
/// </remarks>
public class InvitationBindingHarness : SessionCookieHarness
{
    /// <summary>The name of the OpenID Connect provider.</summary>
    public const string OidcProviderName = "Oidc Idp";

    /// <summary>The scheme of <see cref="OidcProviderName"/>.</summary>
    public const string OidcProviderScheme = "oidc-idp";

    const string OidcIssuer = "https://oidc.test";
    const string OidcClientId = "oidc-client";
    const string OidcAuthorizationEndpoint = "https://oidc.test/authorize";

    readonly RSA _oidcKey = RSA.Create(2048);

    /// <summary>
    /// Gets the nonce the OpenID Connect authorization request carried, which the identity token must echo.
    /// </summary>
    public string OidcNonce { get; private set; } = string.Empty;

    /// <summary>
    /// Plays one whole sign-in through a provider for a person holding a pending invitation, and reads the ticket the session holds.
    /// </summary>
    /// <param name="scheme">The provider scheme to sign in through.</param>
    /// <param name="invitationCapability">The invitation capability the pending invitation cookie carries.</param>
    /// <returns>The properties of the signed-in ticket, or <see langword="null"/> when no session was issued.</returns>
    public async Task<AuthenticationProperties?> SignInForInvitation(string scheme, string invitationCapability)
    {
        using var client = CreateSecurityClient();
        var login = await client.SendAsync(Request(
            ConsoleHost,
            $"{WellKnownPaths.LoginPrefix}/{scheme}?returnUrl=%2F",
            $"{Cookies.InviteToken}={invitationCapability}"));
        var location = login.Headers.Location;
        if (location?.IsAbsoluteUri != true)
        {
            return null;
        }

        var query = QueryHelpers.ParseQuery(location.Query);
        OidcNonce = query.TryGetValue("nonce", out var nonce) ? nonce.ToString() : string.Empty;
        var handshakeCookies = SessionFrom(login);

        // The callback is the provider returning the person, so the pending invitation cookie is deliberately
        // not sent with it: the ticket must hold the binding the challenge put there, not what completing the
        // invitation on the callback would have replaced it with.
        var callback = await client.SendAsync(Request(
            ConsoleHost,
            $"/signin-{scheme}?code=test-code&state={Uri.EscapeDataString(query["state"].ToString())}",
            [.. handshakeCookies]));

        return ReadTicketProperties(callback);
    }

    /// <summary>
    /// Computes the binding AuthProxy writes for an invitation capability.
    /// </summary>
    /// <param name="invitationCapability">The invitation capability.</param>
    /// <returns>The expected capability binding value.</returns>
    public static string ExpectedBinding(string invitationCapability)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{Cookies.InviteToken}={invitationCapability}";
        var properties = new AuthenticationProperties();
        Invites.InvitationAuthenticationState.TryBindPendingInvitation(context, properties);
        return properties.Items[Invites.InvitationAuthenticationState.CapabilityHashStateKey]!;
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder
            .UseSetting($"{C.Authentication.SectionKey}:OidcProviders:0:Name", OidcProviderName)
            .UseSetting($"{C.Authentication.SectionKey}:OidcProviders:0:Authority", OidcIssuer)
            .UseSetting($"{C.Authentication.SectionKey}:OidcProviders:0:ClientId", OidcClientId)
            .UseSetting($"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret", "oidc-secret")
            .ConfigureTestServices(services => services.PostConfigure<OpenIdConnectOptions>(OidcProviderScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration
                {
                    Issuer = OidcIssuer,
                    AuthorizationEndpoint = OidcAuthorizationEndpoint,
                    TokenEndpoint = $"{OidcIssuer}/token",
                };
                configuration.SigningKeys.Add(new RsaSecurityKey(_oidcKey.ExportParameters(false)) { KeyId = "oidc-key" });
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
                options.RequireHttpsMetadata = false;
                options.Backchannel = new HttpClient(new OidcTokenEndpoint(this)) { Timeout = TimeSpan.FromSeconds(10) };
            }));
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _oidcKey.Dispose();
        }
    }

    AuthenticationProperties? ReadTicketProperties(HttpResponseMessage callback)
    {
        var session = SetCookies(callback).FirstOrDefault(_ => IsSettingOf(_, CookieName));
        if (session is null)
        {
            return null;
        }

        var value = Uri.UnescapeDataString(session.Split(';')[0][(CookieName.Length + 1)..]);
        var options = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        return options.TicketDataFormat.Unprotect(value)?.Properties;
    }

    string CreateIdentityToken()
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = OidcIssuer,
            Audience = OidcClientId,
            Expires = DateTime.UtcNow.AddMinutes(5),
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            IssuedAt = DateTime.UtcNow,
            Claims = new Dictionary<string, object> { ["sub"] = "oidc-user-1", ["nonce"] = OidcNonce },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(_oidcKey) { KeyId = "oidc-key" },
                SecurityAlgorithms.RsaSha256),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    sealed class OidcTokenEndpoint(InvitationBindingHarness harness) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["id_token"] = harness.CreateIdentityToken(),
                ["access_token"] = "test-access-token",
                ["token_type"] = "Bearer",
            });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }
}
