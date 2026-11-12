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
        var providers = options.Authentication.OidcProviders
            .Select((provider, index) => (provider.Name, provider.Session, Path: $"Cratis:AuthProxy:Authentication:OidcProviders[{index}]:Session:Lifetime"))
            .Concat(options.Authentication.OAuthProviders
                .Select((provider, index) => (provider.Name, provider.Session, Path: $"Cratis:AuthProxy:Authentication:OAuthProviders[{index}]:Session:Lifetime")));
        var failures = providers
            .Where(provider => provider.Session?.Lifetime is { } lifetime && (lifetime <= TimeSpan.Zero || lifetime > ceiling))
            .Select(provider => DescribeFailure(provider, ceiling))
            .ToArray();
        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static string DescribeFailure((string Name, C.ProviderSession? Session, string Path) provider, TimeSpan ceiling)
    {
        var lifetime = provider.Session!.Lifetime!.Value;
        var reason = lifetime <= TimeSpan.Zero
            ? "must be greater than 00:00:00"
            : "exceeds the global session lifetime";
        return $"Provider '{provider.Name}': {provider.Path} '{lifetime:c}' {reason}. "
            + $"The effective global Cratis:AuthProxy:Session:Lifetime ceiling is '{ceiling:c}'. "
            + $"Set it to a value above 00:00:00 and no longer than '{ceiling:c}', or remove the provider's Session:Lifetime to inherit the global value.";
    }
}
