// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Tenancy;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Identifies backend hosts without extending trust to frontends or registration endpoints.
/// </summary>
internal static class BackendHopHosts
{
    /// <summary>
    /// Collects every backend host, including lobby and tenant-selection back channels.
    /// </summary>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>A case-insensitive host set.</returns>
    internal static IReadOnlySet<string> For(C.AuthProxy config) =>
        config.Services.Values.Select(service => service.Backend?.BaseUrl)
            .Append(config.Invite?.Lobby?.Backend?.BaseUrl)
            .Concat(Selections(config).Select(selection => selection.Options.TenantsEndpoint))
            .Where(address => Uri.TryCreate(address, UriKind.Absolute, out _))
            .Select(address => new Uri(address!, UriKind.Absolute).IdnHost)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Reads selection options using the same conversion as the tenant-selection middleware.
    /// </summary>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>The selection indexes and options.</returns>
    internal static IEnumerable<(int Index, SelectionOptions Options)> Selections(C.AuthProxy config)
    {
        for (var index = 0; index < config.TenantResolutions.Count; index++)
        {
            var resolution = config.TenantResolutions[index];
            if (resolution.Strategy != C.TenantSourceIdentifierResolverType.Selection) continue;
            if (resolution.Options is SelectionOptions options) yield return (index, options);
        }
    }

    /// <summary>
    /// Lists signed identity-bearing destinations with their configuration keys.
    /// </summary>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>The destination names, keys and addresses.</returns>
    internal static IEnumerable<(string Name, string Key, string Address)> SignedHops(C.AuthProxy config) =>
        config.Services.Where(pair => pair.Value.ForwardedIdentity is not null && pair.Value.Backend is not null)
            .Select(pair => (pair.Key, $"{C.AuthProxy.SectionKey}:Services:{pair.Key}:Backend:BaseUrl", pair.Value.Backend!.BaseUrl))
            .Concat(Selections(config).Where(selection => selection.Options.ForwardedIdentity is not null)
                .Select(selection => ($"tenant list {selection.Index}", $"{C.AuthProxy.SectionKey}:TenantResolutions:{selection.Index}:Options:TenantsEndpoint", selection.Options.TenantsEndpoint)));
}
