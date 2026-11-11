// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using Cratis.AuthProxy.SignInCallbacks;
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
    bool _authenticationIsInvalid;
    IAuthenticationService _authenticationService;
    string? _signedOutScheme;
    protected CookieAuthenticationOptions _cookieOptions;

    /// <summary>
    /// The startup-cached named options for the configured OAuth provider.
    /// </summary>
    protected OAuthOptions _oauthOptions;
    protected OpenIdConnectOptions _oidcOptions;
    protected IServiceProvider _services;

    /// <summary>
    /// The principal of the most recently issued OIDC ticket.
    /// </summary>
    protected ClaimsPrincipal? _issuedPrincipal;

    void Establish()
    {
        _authentication = InitialAuthentication();
        var authenticationMonitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationMonitor.CurrentValue.Returns(_ => _authenticationIsInvalid
            ? throw new OptionsValidationException(string.Empty, typeof(C.Authentication), ["invalid"])
            : _authentication);

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
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationParameters:prompt"] = "select_account",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationParameters:audience"] = "workforce",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:ProviderKey"] = OAuthProviderKey,
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:SubjectClaimType"] = "sub",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:Issuer"] = "https://issuer.example.com"
        });
        builder.AddIngressConfiguration();
        builder.Services.AddSingleton(authenticationMonitor);
        builder.Services.AddSingleton(Substitute.For<ISignInNotifier>());
        builder.Services.AddSingleton(Substitute.For<ISignInCallbackDispatcher>());
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
        _issuedPrincipal = ticketContext.Principal;
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

    /// <summary>
    /// Makes every later read of the current authentication configuration fail options validation.
    /// </summary>
    protected void UseInvalidAuthentication() => _authenticationIsInvalid = true;

    /// <summary>
    /// The values of the configured OIDC registration; set only what a specification changes.
    /// </summary>
    protected sealed record OidcRegistration
    {
        public string Name { get; init; } = "Microsoft";

        public string Authority { get; init; } = "https://login.example.com/common/v2.0";

        public string ClientId { get; init; } = "registration-client";

        public string ProviderKey { get; init; } = canonical_cookie_registration.ProviderKey;

        public string SubjectClaimType { get; init; } = "oid";
    }

    /// <summary>
    /// The values of the configured OAuth registration; set only what a specification changes.
    /// </summary>
    protected sealed record OAuthRegistration
    {
        public string AuthorizationEndpoint { get; init; } = "https://oauth.example.com/authorize";

        public string TokenEndpoint { get; init; } = "https://oauth.example.com/token";

        public string UserInformationEndpoint { get; init; } = "https://oauth.example.com/user";

        public string SubjectJsonField { get; init; } = "id";

        public string AuthorizationParameterValue { get; init; } = "select_account";

        public bool ReverseClaimMappingOrder { get; init; }

        public bool ReverseAuthorizationParameterOrder { get; init; }
    }

    protected static C.Authentication InitialAuthentication(OidcRegistration? registration = null)
    {
        registration ??= new();
        return new()
        {
            OidcProviders =
            [
                new C.OidcProvider
                {
                    Name = registration.Name,
                    Authority = registration.Authority,
                    ClientId = registration.ClientId,
                    ClientSecret = ClientSecret,
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = registration.ProviderKey,
                        SubjectClaimType = registration.SubjectClaimType
                    }
                }
            ]
        };
    }

    /// <summary>
    /// Creates the mutable current OAuth registration used to revalidate a ticket against cached named handler options.
    /// </summary>
    /// <param name="registration">The registration values; defaults to the startup registration.</param>
    /// <returns>The current authentication registration.</returns>
    protected static C.Authentication OAuthAuthentication(OAuthRegistration? registration = null)
    {
        registration ??= new();
        return new()
        {
            OAuthProviders =
        [
            new C.OAuthProvider
            {
                Name = "GitHub",
                AuthorizationEndpoint = registration.AuthorizationEndpoint,
                TokenEndpoint = registration.TokenEndpoint,
                UserInformationEndpoint = registration.UserInformationEndpoint,
                ClientId = "registration-client",
                ClientSecret = ClientSecret,
                ClaimMappings = registration.ReverseClaimMappingOrder
                    ? new Dictionary<string, string>
                    {
                        ["name"] = "login",
                        ["sub"] = registration.SubjectJsonField
                    }
                    : new Dictionary<string, string>
                    {
                        ["sub"] = registration.SubjectJsonField,
                        ["name"] = "login"
                    },
                AuthorizationParameters = registration.ReverseAuthorizationParameterOrder
                    ? new Dictionary<string, string>
                    {
                        ["audience"] = "workforce",
                        ["prompt"] = registration.AuthorizationParameterValue
                    }
                    : new Dictionary<string, string>
                    {
                        ["prompt"] = registration.AuthorizationParameterValue,
                        ["audience"] = "workforce"
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
    }

    protected static ClaimsPrincipal CanonicalPrincipal(string issuer = "https://issuer.example.com/tenant-a") =>
        new(new ClaimsIdentity(
        [
            new Claim(CanonicalIdentityClaims.ProviderKey, ProviderKey),
            new Claim(CanonicalIdentityClaims.Issuer, issuer),
            new Claim(CanonicalIdentityClaims.Subject, Subject)
        ],
        ProviderScheme));

    protected static C.Authentication TwoProviderAuthentication() => new()
    {
        OidcProviders = [new C.OidcProvider { Name = "Microsoft", Authority = "https://login.example.com/common/v2.0", ClientId = "registration-client", ClientSecret = ClientSecret }],
        OAuthProviders = [new C.OAuthProvider { Name = "GitHub", ClientId = "registration-client", ClientSecret = ClientSecret }]
    };

    protected static ClaimsPrincipal LegacyPrincipal(string? recordedProvider) =>
        new(new ClaimsIdentity(
            recordedProvider is null ? [new Claim("sub", Subject)] : [new Claim("sub", Subject), new Claim(SessionClaims.ProviderScheme, recordedProvider)],
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
