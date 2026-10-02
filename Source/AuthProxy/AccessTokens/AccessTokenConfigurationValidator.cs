// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Validates every service's <see cref="C.Service.AccessToken"/> at startup.
/// </summary>
/// <param name="authentication">The authentication configuration, naming the OIDC providers tokens can come from.</param>
public class AccessTokenConfigurationValidator(IOptionsMonitor<C.Authentication> authentication) : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var providers = authentication.CurrentValue.OidcProviders;
        var failures = options.Services
            .Where(_ => _.Value.AccessToken is not null)
            .SelectMany(_ => Problems(_.Key, _.Value, providers))
            .ToArray();

        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static IEnumerable<string> Problems(string serviceName, C.Service service, IList<C.OidcProvider> providers)
    {
        var accessToken = service.AccessToken!;

        if (service.Backend is null)
        {
            yield return $"Service '{serviceName}' declares an AccessToken but has no Backend to forward it to.";
        }

        if (accessToken.Scopes.All(string.IsNullOrWhiteSpace) && string.IsNullOrWhiteSpace(accessToken.Resource))
        {
            yield return $"Service '{serviceName}': AccessToken needs Scopes or a Resource naming the backend's audience.";
        }

        if (providers.Count == 0)
        {
            yield return $"Service '{serviceName}' declares an AccessToken, but no OIDC provider is configured to obtain it from.";
        }
        else if (!string.IsNullOrWhiteSpace(accessToken.Provider)
            && !providers.Any(_ => string.Equals(OidcProviderScheme.FromName(_.Name), OidcProviderScheme.FromName(accessToken.Provider), StringComparison.Ordinal)))
        {
            yield return $"Service '{serviceName}': AccessToken.Provider '{accessToken.Provider}' is not a configured OIDC provider.";
        }
    }
}
