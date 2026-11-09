// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Owns the configured v2 tenancy header at both gateway boundaries.</summary>
internal static class ForwardedIdentityTenantHeader
{
    const string TokenPunctuation = "!#$%&'*+-.^_`|~";
    static readonly string[] _reserved = ["Authorization", "DPoP", "Cookie", "Host", "Content-Length", "Content-Type", "Transfer-Encoding", "Connection", Headers.TokenClientId, Headers.TokenScope, Headers.ServiceId, Headers.LegacyServiceId];

    /// <summary>Checks that tenancy cannot overwrite authentication, framing or another signed fact.</summary>
    /// <param name="name">The configured receiver header.</param>
    /// <returns>Whether it is a usable header name.</returns>
    internal static bool IsValid(string name) => !string.IsNullOrEmpty(name) && name.Length <= 256
        && name.All(character => char.IsAsciiLetterOrDigit(character) || TokenPunctuation.Contains(character, StringComparison.Ordinal))
        && !IsReserved(name.Replace('_', '-'));

    /// <summary>Strips every configured tenant header, including flows not selected by this request.</summary>
    /// <param name="headers">The inbound headers.</param>
    /// <param name="config">The current gateway configuration.</param>
    internal static void Strip(IHeaderDictionary headers, C.AuthProxy config)
    {
        foreach (var settings in config.Services.Values.Select(service => service.ForwardedIdentity))
        {
            if (settings?.Version == "v2" && IsValid(settings.TenantHeader)) Strip(headers, settings.TenantHeader);
        }
        if (TenantSelectionMiddleware.TryGetSelectionOptions(config, out var selection)
            && selection.ForwardedIdentity is { } tenantList && tenantList.Version == "v2" && IsValid(tenantList.TenantHeader))
        {
            Strip(headers, tenantList.TenantHeader);
        }
    }

    /// <summary>Replaces the custom header with the gateway-authored tenant, never a copied inbound value.</summary>
    /// <param name="request">The final outgoing request.</param>
    /// <param name="name">The configured tenancy header.</param>
    /// <returns>Whether the tenant could be set without ambiguity.</returns>
    internal static bool Apply(HttpRequestMessage request, string name)
    {
        if (!IsValid(name)) return false;
        if (name.Equals(Headers.TenantId, StringComparison.OrdinalIgnoreCase)) return true;
        request.Headers.Remove(name);
        request.Content?.Headers.Remove(name);
        if (!request.Headers.TryGetValues(Headers.TenantId, out var values)) return true;
        var tenants = values.Take(2).ToArray();
        return tenants.Length == 1 && request.Headers.TryAddWithoutValidation(name, tenants[0]);
    }

    static bool IsReserved(string name) => name.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase)
        || name.StartsWith(Headers.OnBehalfPrefix, StringComparison.OrdinalIgnoreCase)
        || name.Equals(Headers.ForwardedIdentitySignature, StringComparison.OrdinalIgnoreCase)
        || ForwardedIdentityV2ContextHeaders.Names.Contains(name, StringComparer.OrdinalIgnoreCase)
        || _reserved.Contains(name, StringComparer.OrdinalIgnoreCase);

    static void Strip(IHeaderDictionary headers, string name)
    {
        foreach (var key in headers.Keys.Where(key => key.Replace('_', '-').Equals(name.Replace('_', '-'), StringComparison.OrdinalIgnoreCase)).ToArray()) headers.Remove(key);
    }
}
