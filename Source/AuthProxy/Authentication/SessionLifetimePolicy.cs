// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Represents the effective shorten-only policy for an issued browser session.</summary>
/// <param name="Lifetime">The ticket lifetime, bounded by the global ceiling.</param>
/// <param name="Sliding">Whether the global and provider settings both permit renewal.</param>
/// <param name="IsOverride">Whether the effective policy differs from the global settings.</param>
internal sealed record SessionLifetimePolicy(TimeSpan Lifetime, bool Sliding, bool IsOverride)
{
    /// <summary>Combines deployment-configured global and provider settings.</summary>
    /// <param name="global">The global session policy.</param>
    /// <param name="provider">The optional provider override.</param>
    /// <returns>The effective shorten-only policy.</returns>
    internal static SessionLifetimePolicy Resolve(C.Session global, C.ProviderSession? provider)
    {
        var ceiling = global.Lifetime > TimeSpan.Zero ? global.Lifetime : C.Session.DefaultLifetime;
        var lifetime = provider?.Lifetime is { } requested && requested < ceiling ? requested : ceiling;
        var sliding = global.SlidingExpiration && (provider?.SlidingExpiration ?? true);
        return new(lifetime, sliding, lifetime != ceiling || sliding != global.SlidingExpiration);
    }

    /// <summary>Resolves a trusted provider scheme, choosing the most restrictive matching registration.</summary>
    /// <param name="global">The global session policy.</param>
    /// <param name="authentication">The configured providers.</param>
    /// <param name="scheme">The server-selected authentication scheme.</param>
    /// <returns>The effective policy, or the global policy for an unknown scheme.</returns>
    internal static SessionLifetimePolicy Resolve(C.Session global, C.Authentication authentication, string scheme)
    {
        var providers = authentication.OidcProviders.Select(provider => (provider.Name, provider.Session))
            .Concat(authentication.OAuthProviders.Select(provider => (provider.Name, provider.Session)))
            .Where(provider => OidcProviderScheme.FromName(provider.Name).Equals(scheme, StringComparison.OrdinalIgnoreCase));
        var result = Resolve(global, null);

        // Duplicate names must not let a less restrictive registration extend a session.
        foreach (var provider in providers)
        {
            var candidate = Resolve(global, provider.Session);
            result = new(
                candidate.Lifetime < result.Lifetime ? candidate.Lifetime : result.Lifetime,
                result.Sliding && candidate.Sliding,
                result.IsOverride || candidate.IsOverride);
        }
        return result;
    }

    /// <summary>Shortens successful sign-in properties without changing an inherited policy.</summary>
    /// <param name="properties">The final server-owned authentication properties.</param>
    /// <param name="clock">The authentication clock.</param>
    internal void Apply(AuthenticationProperties properties, TimeProvider clock)
    {
        if (!IsOverride) return;
        properties.IssuedUtc ??= clock.GetUtcNow();
        var deadline = properties.IssuedUtc.Value.Add(Lifetime);
        if (properties.ExpiresUtc is null || properties.ExpiresUtc > deadline)
        {
            properties.ExpiresUtc = deadline;
        }
        if (!Sliding) properties.AllowRefresh = false;
    }
}
