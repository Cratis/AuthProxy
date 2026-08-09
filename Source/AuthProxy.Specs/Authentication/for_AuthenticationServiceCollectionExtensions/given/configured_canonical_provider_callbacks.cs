// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

/// <summary>
/// Provides the real configured OIDC and OAuth callback delegates with canonical identity dependencies.
/// </summary>
public class configured_canonical_provider_callbacks : Specification
{
    protected const string ValidatedIssuer = "https://validated.example.com/tenant";

    protected OpenIdConnectOptions _oidcOptions;
    protected OAuthOptions _oauthOptions;
    protected IServiceProvider _services;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Microsoft",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.com/tenant",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "oidc-client",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret"] = "oidc-secret",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:ProviderKey"] = "entra-workforce",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:SubjectClaimType"] = "oid",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = "GitHub",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "https://github.example.com/authorize",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "https://github.example.com/token",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint"] = "https://github.example.com/user",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "oauth-client",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret"] = "oauth-secret",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:ProviderKey"] = "github-workforce",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:SubjectClaimType"] = "id",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:Issuer"] = "https://github.example.com"
        });

        var rootConfiguration = new C.AuthProxy
        {
            Authentication = new C.Authentication
            {
                OidcProviders =
                [
                    new C.OidcProvider
                    {
                        Name = "Microsoft",
                        CanonicalIdentity = new C.CanonicalIdentity
                        {
                            ProviderKey = "entra-workforce",
                            SubjectClaimType = "oid"
                        }
                    }
                ],
                OAuthProviders =
                [
                    new C.OAuthProvider
                    {
                        Name = "GitHub",
                        CanonicalIdentity = new C.CanonicalIdentity
                        {
                            ProviderKey = "github-workforce",
                            SubjectClaimType = "id",
                            Issuer = "https://github.example.com"
                        }
                    }
                ]
            }
        };
        var rootOptions = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        rootOptions.CurrentValue.Returns(rootConfiguration);
        builder.Services.AddSingleton(rootOptions);
        builder.Services.AddSingleton<ISignInNotifier>(Substitute.For<ISignInNotifier>());
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        _services = builder.Services.BuildServiceProvider();
        _oidcOptions = _services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("microsoft");
        _oauthOptions = _services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get("github");
    }

    protected DefaultHttpContext Context() => new() { RequestServices = _services };

    protected static TicketReceivedContext TicketContext(
        DefaultHttpContext context,
        string schemeName,
        RemoteAuthenticationOptions options,
        ClaimsPrincipal principal,
        AuthenticationProperties properties)
    {
        var scheme = new AuthenticationScheme(schemeName, schemeName, typeof(OpenIdConnectHandler));
        return new TicketReceivedContext(
            context,
            scheme,
            options,
            new AuthenticationTicket(principal, properties, schemeName));
    }
}
