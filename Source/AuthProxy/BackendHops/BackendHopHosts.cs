// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Tenancy;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Identifies backend and signed frontend hosts without extending trust to unsigned frontends or registration endpoints.
/// </summary>
internal static class BackendHopHosts
{
    /// <summary>
    /// Collects every backend host and signed frontend, including lobby and tenant-selection back channels.
    /// </summary>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>A case-insensitive host set.</returns>
    internal static IReadOnlySet<string> For(C.AuthProxy config) =>
        config.Services.Values.Select(service => service.Backend?.BaseUrl)
            .Concat(config.Services.Values.Where(service => service.ForwardedIdentity is not null).Select(service => service.Frontend?.BaseUrl))
            .Append(config.Invite?.Lobby?.Backend?.BaseUrl)
            .Concat(Selections(config).Select(selection => selection.Options.TenantsEndpoint))
            .Concat(IsSigningConfigured(config) ? new[] { config.Invite?.StageUrl, config.Invite?.ExchangeUrl, config.Link?.ExchangeUrl, config.SignIn?.NotifyUrl } : [])
            .Where(address => Uri.TryCreate(address, UriKind.Absolute, out _))
            .Select(address => new Uri(address!, UriKind.Absolute).IdnHost)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Determines whether any outbound destination configures forwarded-identity signing.</summary>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>Whether signing is configured.</returns>
    internal static bool IsSigningConfigured(C.AuthProxy config) => SignedHops(config).Any();

    /// <summary>Determines whether identity back channels require HTTPS.</summary>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>Whether the deployment requires HTTPS.</returns>
    internal static bool RequiresHttps(C.AuthProxy config) => IsSigningConfigured(config) && config.Profile != C.DeploymentProfile.LocalDevelopment;

    /// <summary>Determines whether a destination uses HTTPS.</summary>
    /// <param name="address">The absolute destination address.</param>
    /// <returns>Whether the address is an absolute HTTPS URI.</returns>
    internal static bool IsHttps(string address) => Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;

    /// <summary>Checks a resolved identity back channel against the deployment's transport policy.</summary>
    /// <param name="config">The deployment configuration.</param>
    /// <param name="address">The resolved destination address.</param>
    /// <returns>Whether the destination meets the transport policy.</returns>
    internal static bool AllowsIdentityBackChannel(C.AuthProxy config, string address) => !RequiresHttps(config) || IsHttps(address);

    /// <summary>Lists identity back channels and verifier destinations with their configuration keys.</summary>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>The distinct destination names, keys and addresses.</returns>
    internal static IEnumerable<(string Name, string Key, string Address)> IdentityBackChannels(C.AuthProxy config) =>
        ServiceBackChannels(config)
            .Concat(OnBehalfChannels(config))
            .Concat(BodyAndVerifierChannels(config))
            .Concat(SubHostVerifierChannels(config))
            .DistinctBy(channel => channel.Key);

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
    internal static IEnumerable<(string Name, string Key, string Address)> SignedHops(C.AuthProxy config)
    {
        foreach (var (name, service) in config.Services)
        {
            if (service.ForwardedIdentity is null) continue;
            if (service.Backend is not null) yield return (name, $"{C.AuthProxy.SectionKey}:Services:{name}:Backend:BaseUrl", service.Backend.BaseUrl);
            if (service.Frontend is not null) yield return (name, $"{C.AuthProxy.SectionKey}:Services:{name}:Frontend:BaseUrl", service.Frontend.BaseUrl);
        }
        foreach (var (index, options) in Selections(config).Where(selection => selection.Options.ForwardedIdentity is not null))
        {
            yield return ($"tenant list {index}", $"{C.AuthProxy.SectionKey}:TenantResolutions:{index}:Options:TenantsEndpoint", options.TenantsEndpoint);
        }
    }

    static IEnumerable<(string Name, string Key, string Address)> ServiceBackChannels(C.AuthProxy config)
    {
        foreach (var (name, service) in config.Services)
        {
            if (service.Backend is null) continue;
            if (service.SignInCallback is not null) yield return ($"sign-in callback {name}", $"{C.AuthProxy.SectionKey}:Services:{name}:Backend:BaseUrl", service.Backend.BaseUrl);
            if (service.ClientCredentials is { } credentials)
            {
                var endpoint = ClientCredentialsServiceResolver.CreateVerificationUri(service.Backend.BaseUrl, credentials.VerificationPath);
                yield return ($"client credentials {name}", $"{C.AuthProxy.SectionKey}:Services:{name}:ClientCredentials:VerificationPath", endpoint?.AbsoluteUri ?? credentials.VerificationPath);
            }
        }
    }

    static IEnumerable<(string Name, string Key, string Address)> OnBehalfChannels(C.AuthProxy config)
    {
        if (config.OnBehalf is not { } onBehalf) yield break;
        if (!config.Services.TryGetValue(onBehalf.Service, out var application)) yield break;
        if (application is { ForwardedIdentity: not null, Backend: { } backend })
        {
            yield return ($"on-behalf {onBehalf.Service}", $"{C.AuthProxy.SectionKey}:Services:{onBehalf.Service}:Backend:BaseUrl", backend.BaseUrl);
        }
    }

    static IEnumerable<(string Name, string Key, string Address)> BodyAndVerifierChannels(C.AuthProxy config)
    {
        var endpoints = new (string Key, string? Address)[]
        {
            ("Invite:StageUrl", config.Invite?.StageUrl),
            ("Invite:ExchangeUrl", config.Invite?.ExchangeUrl),
            ("Link:ExchangeUrl", config.Link?.ExchangeUrl),
            ("SignIn:NotifyUrl", config.SignIn?.NotifyUrl),
            ("Admission:Capability:VerifierUrl", config.Admission?.Capability?.VerifierUrl),
            ("TenantVerification:UrlTemplate", config.TenantVerification?.UrlTemplate)
        };
        foreach (var (key, address) in endpoints)
        {
            if (!string.IsNullOrWhiteSpace(address)) yield return (key, $"{C.AuthProxy.SectionKey}:{key}", address);
        }
    }

    static IEnumerable<(string Name, string Key, string Address)> SubHostVerifierChannels(C.AuthProxy config)
    {
        for (var index = 0; index < config.TenantResolutions.Count; index++)
        {
            if (config.TenantResolutions[index].Options is SubHostOptions { VerificationUrlTemplate: { } template } && !string.IsNullOrWhiteSpace(template))
            {
                yield return ($"tenant verification {index}", $"{C.AuthProxy.SectionKey}:TenantResolutions:{index}:Options:VerificationUrlTemplate", template);
            }
        }
    }
}
