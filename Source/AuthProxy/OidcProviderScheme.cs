// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Provides helper methods for working with OIDC provider schemes.
/// </summary>
public static class OidcProviderScheme
{
    /// <summary>
    /// Derives the OIDC authentication scheme name from the provider's display name.
    /// Converts to lowercase and replaces spaces with dashes.
    /// </summary>
    /// <param name="providerName">The display name of the provider.</param>
    /// <returns>A URL-safe scheme name string.</returns>
    public static string FromName(string providerName) =>
        providerName.ToLowerInvariant().Replace(" ", "-", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Builds the <see cref="OidcProviderInfo"/> for a given <see cref="C.OidcProvider"/>,
    /// computing the login URL based on the scheme name.
    /// </summary>
    /// <param name="provider">The provider configuration.</param>
    /// <returns>A populated <see cref="OidcProviderInfo"/> instance.</returns>
    public static OidcProviderInfo ToProviderInfo(C.OidcProvider provider)
    {
        var scheme = FromName(provider.Name);
        var loginUrl = $"{WellKnownPaths.LoginPrefix}/{scheme}";
        return new OidcProviderInfo(provider.Name, provider.Type, loginUrl);
    }

    /// <summary>
    /// Builds the <see cref="OidcProviderInfo"/> for a given <see cref="C.OAuthProvider"/>,
    /// computing the login URL based on the scheme name.
    /// </summary>
    /// <param name="provider">The provider configuration.</param>
    /// <returns>A populated <see cref="OidcProviderInfo"/> instance.</returns>
    public static OidcProviderInfo ToProviderInfo(C.OAuthProvider provider)
    {
        var scheme = FromName(provider.Name);
        var loginUrl = $"{WellKnownPaths.LoginPrefix}/{scheme}";
        return new OidcProviderInfo(provider.Name, provider.Type, loginUrl);
    }
}
