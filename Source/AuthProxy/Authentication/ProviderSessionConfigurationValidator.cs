// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Validates provider browser-session overrides against the global lifetime ceiling.</summary>
public class ProviderSessionConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var ceiling = options.Session.Lifetime > TimeSpan.Zero ? options.Session.Lifetime : C.Session.DefaultLifetime;
        var providers = options.Authentication.OidcProviders.Select(provider => (provider.Name, provider.Session))
            .Concat(options.Authentication.OAuthProviders.Select(provider => (provider.Name, provider.Session)));
        var failures = providers
            .Where(provider => provider.Session?.Lifetime is { } lifetime && (lifetime <= TimeSpan.Zero || lifetime > ceiling))
            .Select(provider => $"Provider '{provider.Name}' session lifetime must be positive and no longer than the global session lifetime.")
            .ToArray();
        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
