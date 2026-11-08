// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The ready-made profile for an OIDC provider of type <see cref="C.OidcProviderType.CratisIdentity"/>.
/// </summary>
/// <remarks>
/// The profile is opt-in: it changes nothing for a provider of any other type. A Cratis Identity provider signs people in
/// with the authorization-code flow and PKCE as a confidential client, requests only <c language="text">openid profile</c>
/// plus the scopes the provider configures, accepts a discovery document only when it names the configured authority as its
/// issuer, and maps the account <c language="text">sub</c> to the canonical identity claims unless the provider configures
/// its own canonical identity contract. Sign-out uses the discovered end-session endpoint like every OIDC provider.
/// </remarks>
public static class CratisIdentityProfile
{
    /// <summary>
    /// The claim type the profile selects as the account subject.
    /// </summary>
    public const string SubjectClaimType = "sub";

    /// <summary>
    /// The scopes the profile always requests.
    /// </summary>
    internal static readonly string[] DefaultScopes = ["openid", "profile"];

    /// <summary>
    /// Determines whether the profile applies to a provider.
    /// </summary>
    /// <param name="provider">The provider configuration.</param>
    /// <returns><see langword="true"/> when the provider is a Cratis Identity provider; otherwise <see langword="false"/>.</returns>
    public static bool AppliesTo(C.OidcProvider provider) => provider.Type == C.OidcProviderType.CratisIdentity;

    /// <summary>
    /// Fills in the canonical identity contract of every Cratis Identity provider that does not configure one: the
    /// provider key is the provider's scheme and the subject is the <c language="text">sub</c> claim.
    /// </summary>
    /// <param name="providers">The configured OIDC providers to complete.</param>
    public static void ApplyDefaults(IEnumerable<C.OidcProvider> providers)
    {
        foreach (var provider in providers.Where(_ => AppliesTo(_) && _.CanonicalIdentity is null))
        {
            provider.CanonicalIdentity = new C.CanonicalIdentity
            {
                ProviderKey = OidcProviderScheme.FromName(provider.Name),
                SubjectClaimType = SubjectClaimType,
            };
        }
    }

    /// <summary>
    /// Applies the profile to the OpenID Connect handler options of a Cratis Identity provider.
    /// </summary>
    /// <param name="options">The handler options.</param>
    /// <param name="provider">The provider configuration.</param>
    public static void Configure(OpenIdConnectOptions options, C.OidcProvider provider)
    {
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;

        // The startup validator refuses a non-HTTPS authority outside the LocalDevelopment profile, so relaxing the
        // metadata requirement here only ever serves a local development realm.
        options.RequireHttpsMetadata = !Uri.TryCreate(provider.Authority, UriKind.Absolute, out var authority)
            || authority.Scheme != Uri.UriSchemeHttp;

        options.Scope.Clear();
        foreach (var scope in DefaultScopes.Concat(provider.Scopes).Distinct(StringComparer.Ordinal))
        {
            options.Scope.Add(scope);
        }
    }

    /// <summary>
    /// Replaces the discovery configuration manager with one that refuses a discovery document whose issuer is not the
    /// configured authority. Runs after the framework has created the back channel and the metadata address.
    /// </summary>
    /// <param name="options">The handler options.</param>
    /// <param name="provider">The provider configuration.</param>
    public static void UseVerifiedDiscovery(OpenIdConnectOptions options, C.OidcProvider provider)
    {
        if (options.Configuration is not null || string.IsNullOrWhiteSpace(options.MetadataAddress))
        {
            return;
        }

        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            options.MetadataAddress,
            new CratisIdentityDiscoveryRetriever(provider.Authority),
            new HttpDocumentRetriever(options.Backchannel) { RequireHttps = options.RequireHttpsMetadata })
        {
            RefreshInterval = options.RefreshInterval,
            AutomaticRefreshInterval = options.AutomaticRefreshInterval,
        };
    }
}
