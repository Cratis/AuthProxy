// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Resolves the OIDC end-session endpoint by consulting the configured providers and the corresponding
/// <see cref="OpenIdConnectOptions"/> discovery document.
/// </summary>
/// <param name="authConfig">The authentication configuration monitor, used to tell OIDC providers apart from OAuth providers.</param>
/// <param name="oidcOptions">The monitor for the per-scheme <see cref="OpenIdConnectOptions"/>.</param>
/// <param name="logger">The logger.</param>
public class EndSessionEndpointResolver(
    IOptionsMonitor<C.Authentication> authConfig,
    IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
    ILogger<EndSessionEndpointResolver> logger) : IEndSessionEndpointResolver
{
    /// <inheritdoc/>
    public async Task<string?> Resolve(string? scheme, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(scheme))
        {
            return null;
        }

        // Only OIDC providers expose a standard end-session endpoint. OAuth 2.0 providers such as GitHub
        // cannot be force-logged-out via a redirect, so anything that is not a configured OIDC provider
        // resolves to null and the caller performs a local-only logout.
        var isOidcProvider = authConfig.CurrentValue.OidcProviders
            .Any(provider => OidcProviderScheme.FromName(provider.Name) == scheme);
        if (!isOidcProvider)
        {
            return null;
        }

        var options = oidcOptions.Get(scheme);
        if (options.ConfigurationManager is null)
        {
            return null;
        }

        try
        {
            var configuration = await options.ConfigurationManager.GetConfigurationAsync(cancellationToken);
            return string.IsNullOrWhiteSpace(configuration.EndSessionEndpoint)
                ? null
                : configuration.EndSessionEndpoint;
        }
        catch (Exception ex)
        {
            // Discovery is best-effort: a provider that is unreachable or omits the end-session endpoint must
            // never break logout. Fall back to a local-only logout instead.
            logger.EndSessionDiscoveryFailed(scheme, ex);
            return null;
        }
    }
}
