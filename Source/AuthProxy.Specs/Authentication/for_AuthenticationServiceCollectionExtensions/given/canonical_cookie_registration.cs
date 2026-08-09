// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

/// <summary>
/// Provides the real cookie authentication events and mutable canonical provider registration for continuity specifications.
/// </summary>
public class canonical_cookie_registration : Specification
{
    protected const string ClientSecret = "registration-client-secret";

    /// <summary>
    /// The derived scheme for the configured OAuth provider.
    /// </summary>
    protected const string OAuthProviderScheme = "github";

    /// <summary>
    /// The canonical provider key for the configured OAuth provider.
    /// </summary>
    protected const string OAuthProviderKey = "github-workforce";
    protected const string ProviderScheme = "microsoft";
    protected const string ProviderKey = "entra-workforce";
    protected const string Subject = "subject-42";

    C.Authentication _authentication;
    IAuthenticationService _authenticationService;
    string? _signedOutScheme;
    protected CookieAuthenticationOptions _cookieOptions;

    /// <summary>
    /// The startup-cached named options for the configured OAuth provider.
    /// </summary>
    protected OAuthOptions _oauthOptions;
    protected OpenIdConnectOptions _oidcOptions;
    protected IServiceProvider _services;

    void Establish()
    {
        _authentication = InitialAuthentication();
        var authenticationMonitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationMonitor.CurrentValue.Returns(_ => _authentication);

        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Microsoft",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.com/common/v2.0",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "registration-client",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret"] = ClientSecret,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:ProviderKey"] = ProviderKey,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:SubjectClaimType"] = "oid",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = "GitHub",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "https://oauth.example.com/authorize",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "https://oauth.example.com/token",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint"] = "https://oauth.example.com/user",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "registration-client",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret"] = ClientSecret,
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClaimMappings:sub"] = "id",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClaimMappings:name"] = "login",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:ProviderKey"] = OAuthProviderKey,
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:SubjectClaimType"] = "sub",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:Issuer"] = "https://issuer.example.com"
        });
        builder.AddIngressConfiguration();
        builder.Services.AddSingleton(authenticationMonitor);
        builder.Services.AddSingleton(Substitute.For<ISignInNotifier>());
        builder.AddIngressAuthentication();
        _authenticationService = Substitute.For<IAuthenticationService>();
        _authenticationService
            .SignOutAsync(Arg.Any<HttpContext>(), Arg.Any<string?>(), Arg.Any<AuthenticationProperties?>())
            .Returns(callInfo =>
            {
                _signedOutScheme = callInfo.ArgAt<string?>(1);
                return Task.CompletedTask;
            });
        builder.Services.AddSingleton(_authenticationService);
        _services = builder.Services.BuildServiceProvider();
        _cookieOptions = _services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        _oidcOptions = _services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(ProviderScheme);
        _oauthOptions = _services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get(OAuthProviderScheme);
    }

    protected async Task<AuthenticationProperties> IssueCanonicalTicket(string issuer = "https://issuer.example.com/tenant-a")
    {
        var httpContext = Context();
        var properties = new AuthenticationProperties();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", Subject)], ProviderScheme));
        var providerScheme = new AuthenticationScheme(ProviderScheme, ProviderScheme, typeof(OpenIdConnectHandler));
        var tokenContext = new TokenValidatedContext(
            httpContext,
            providerScheme,
            _oidcOptions,
            principal,
            properties)
        {
            SecurityToken = new JwtSecurityToken(issuer: issuer)
        };
        await _oidcOptions.Events.OnTokenValidated(tokenContext);

        var ticketContext = new TicketReceivedContext(
            httpContext,
            providerScheme,
            _oidcOptions,
            new AuthenticationTicket(principal, properties, ProviderScheme));
        await _oidcOptions.Events.OnTicketReceived(ticketContext);
        return ticketContext.Properties!;
    }

    /// <summary>
    /// Issues a canonical OAuth ticket through the registered provider callback and stamps its registration continuity state.
    /// </summary>
    /// <returns>The authentication properties persisted with the canonical OAuth ticket.</returns>
    protected async Task<AuthenticationProperties> IssueCanonicalOAuthTicket()
    {
        UseAuthentication(OAuthAuthentication());
        var httpContext = Context();
        var properties = new AuthenticationProperties();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", Subject)], OAuthProviderScheme));
        var providerScheme = new AuthenticationScheme(OAuthProviderScheme, OAuthProviderScheme, typeof(OAuthHandler<OAuthOptions>));
        var ticketContext = new TicketReceivedContext(
            httpContext,
            providerScheme,
            _oauthOptions,
            new AuthenticationTicket(principal, properties, OAuthProviderScheme));
        await _oauthOptions.Events.OnTicketReceived(ticketContext);
        return ticketContext.Properties!;
    }

    /// <summary>
    /// Validates a cookie ticket and reports whether rejection signed out the cookie scheme.
    /// </summary>
    /// <param name="principal">The principal carried by the cookie ticket.</param>
    /// <param name="properties">The authentication properties carried by the cookie ticket.</param>
    /// <returns>The acceptance result and the authentication scheme passed to sign-out, if any.</returns>
    protected async Task<(bool Accepted, string? SignedOutScheme)> Validate(
        ClaimsPrincipal principal,
        AuthenticationProperties properties)
    {
        _signedOutScheme = null;
        var ticket = new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);
        var context = new CookieValidatePrincipalContext(Context(), CookieScheme(), _cookieOptions, ticket);
        await _cookieOptions.Events.OnValidatePrincipal(context);
        return (context.Principal is not null, _signedOutScheme);
    }

    protected async Task<bool> IsAccepted(ClaimsPrincipal principal, AuthenticationProperties properties) =>
        (await Validate(principal, properties)).Accepted;

    protected KeyValuePair<string, string?> Fingerprint(AuthenticationProperties properties) =>
        properties.Items.Single(_ =>
            !string.Equals(
                _.Key,
                AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey,
                StringComparison.Ordinal)
            && _.Value?.StartsWith("v1:", StringComparison.Ordinal) == true);

    protected void UseAuthentication(C.Authentication authentication) => _authentication = authentication;

    protected static C.Authentication InitialAuthentication(
        string name = "Microsoft",
        string authority = "https://login.example.com/common/v2.0",
        string clientId = "registration-client",
        string providerKey = ProviderKey,
        string subjectClaimType = "oid") => new()
        {
            OidcProviders =
            [
                new C.OidcProvider
                {
                    Name = name,
                    Authority = authority,
                    ClientId = clientId,
                    ClientSecret = ClientSecret,
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = providerKey,
                        SubjectClaimType = subjectClaimType
                    }
                }
            ]
        };

    /// <summary>
    /// Creates the mutable current OAuth registration used to revalidate a ticket against cached named handler options.
    /// </summary>
    /// <param name="authorizationEndpoint">The configured authorization endpoint.</param>
    /// <param name="tokenEndpoint">The configured token endpoint.</param>
    /// <param name="userInformationEndpoint">The configured user-information endpoint.</param>
    /// <param name="subjectJsonField">The user-information JSON field mapped to the canonical subject claim.</param>
    /// <param name="reverseClaimMappingOrder">Whether to insert the unchanged claim mappings in reverse order.</param>
    /// <returns>The current authentication registration.</returns>
    protected static C.Authentication OAuthAuthentication(
        string authorizationEndpoint = "https://oauth.example.com/authorize",
        string tokenEndpoint = "https://oauth.example.com/token",
        string userInformationEndpoint = "https://oauth.example.com/user",
        string subjectJsonField = "id",
        bool reverseClaimMappingOrder = false) => new()
    {
        OAuthProviders =
        [
            new C.OAuthProvider
            {
                Name = "GitHub",
                AuthorizationEndpoint = authorizationEndpoint,
                TokenEndpoint = tokenEndpoint,
                UserInformationEndpoint = userInformationEndpoint,
                ClientId = "registration-client",
                ClientSecret = ClientSecret,
                ClaimMappings = reverseClaimMappingOrder
                    ? new Dictionary<string, string>
                    {
                        ["name"] = "login",
                        ["sub"] = subjectJsonField
                    }
                    : new Dictionary<string, string>
                    {
                        ["sub"] = subjectJsonField,
                        ["name"] = "login"
                    },
                CanonicalIdentity = new C.CanonicalIdentity
                {
                    ProviderKey = OAuthProviderKey,
                    SubjectClaimType = "sub",
                    Issuer = "https://issuer.example.com"
                }
            }
        ]
    };

    protected static ClaimsPrincipal CanonicalPrincipal(string issuer = "https://issuer.example.com/tenant-a") =>
        new(new ClaimsIdentity(
        [
            new Claim(CanonicalIdentityClaims.ProviderKey, ProviderKey),
            new Claim(CanonicalIdentityClaims.Issuer, issuer),
            new Claim(CanonicalIdentityClaims.Subject, Subject)
        ],
        ProviderScheme));

    protected static ClaimsPrincipal LegacyPrincipal() =>
        new(new ClaimsIdentity([new Claim("sub", Subject)], ProviderScheme));

    /// <summary>
    /// Creates the canonical principal emitted by the configured OAuth registration.
    /// </summary>
    /// <returns>The canonical OAuth principal.</returns>
    protected static ClaimsPrincipal CanonicalOAuthPrincipal() =>
        new(new ClaimsIdentity(
        [
            new Claim(CanonicalIdentityClaims.ProviderKey, OAuthProviderKey),
            new Claim(CanonicalIdentityClaims.Issuer, "https://issuer.example.com"),
            new Claim(CanonicalIdentityClaims.Subject, Subject)
        ],
        OAuthProviderScheme));

    DefaultHttpContext Context() => new() { RequestServices = _services };

    static AuthenticationScheme CookieScheme() => new(
        CookieAuthenticationDefaults.AuthenticationScheme,
        CookieAuthenticationDefaults.AuthenticationScheme,
        typeof(CookieAuthenticationHandler));
}
