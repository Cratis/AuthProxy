// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Refuses unusable or cross-application signing settings before serving traffic.</summary>
public sealed class ForwardedIdentitySigningConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();
        var services = ValidateServices(options, failures);
        ValidateTenantSelection(options, services, failures);
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static List<(ForwardedIdentitySigningKey Key, string Path, C.Service Service)> ValidateServices(C.AuthProxy options, List<string> failures)
    {
        var services = new List<(ForwardedIdentitySigningKey Key, string Path, C.Service Service)>();
        foreach (var (serviceName, service) in options.Services)
        {
            var path = $"{C.AuthProxy.SectionKey}:Services:{serviceName}";
            var key = Validate(service.ForwardedIdentity, path, failures);
            if (key is null) continue;
            foreach (var existing in services)
            {
                if (SameSecret(existing.Key, key) && !IsAlias(existing.Key, key, existing.Service.Backend, service.Backend))
                {
                    failures.Add($"{existing.Path}:ForwardedIdentity; {path}:ForwardedIdentity");
                }
            }
            services.Add((key, path, service));
        }
        return services;
    }

    static void ValidateTenantSelection(C.AuthProxy options, List<(ForwardedIdentitySigningKey Key, string Path, C.Service Service)> services, List<string> failures)
    {
        if (!TenantSelectionMiddleware.TryGetSelectionOptions(options, out var selection)) return;
        var resolution = options.TenantResolutions.First(resolution => resolution.Strategy == C.TenantSourceIdentifierResolverType.Selection);
        var index = options.TenantResolutions.IndexOf(resolution);
        var path = $"{C.AuthProxy.SectionKey}:TenantResolutions:{index}:Options";
        var key = Validate(selection.ForwardedIdentity, path, failures);
        if (key is null) return;
        foreach (var service in services)
        {
            if (SameSecret(service.Key, key) && !IsOwnBackend(service.Key, key, service.Service.Backend, selection.TenantsEndpoint))
            {
                failures.Add($"{service.Path}:ForwardedIdentity; {path}:ForwardedIdentity");
            }
        }
    }

    static ForwardedIdentitySigningKey? Validate(C.ForwardedIdentitySigning? settings, string path, List<string> failures)
    {
        if (settings is null) return null;
        if (ForwardedIdentitySigningKey.TryCreate(settings, out var key, out var problem)) return key;
        failures.Add($"{path}:{problem}");
        return null;
    }

    static bool SameSecret(ForwardedIdentitySigningKey first, ForwardedIdentitySigningKey second) =>
        CryptographicOperations.FixedTimeEquals(first.Secret.Span, second.Secret.Span);

    static bool IsAlias(ForwardedIdentitySigningKey first, ForwardedIdentitySigningKey second, C.ServiceEndpoint? firstBackend, C.ServiceEndpoint? secondBackend) =>
        string.Equals(first.Audience, second.Audience, StringComparison.Ordinal) &&
        string.Equals(first.KeyId, second.KeyId, StringComparison.Ordinal) &&
        SameBackend(firstBackend, secondBackend);

    static bool SameBackend(C.ServiceEndpoint? first, C.ServiceEndpoint? second)
    {
        if (!TryGetBackendAddress(first, out var firstUri) || !TryGetBackendAddress(second, out var secondUri)) return false;
        return SameOrigin(firstUri, secondUri) && string.Equals(firstUri.AbsolutePath, secondUri.AbsolutePath, StringComparison.Ordinal);
    }

    static bool TryGetBackendAddress(C.ServiceEndpoint? backend, out Uri address)
    {
        address = null!;

        // DNS-discovered replicas do not identify a single destination that can establish alias ownership.
        if (backend?.StickyRouting?.Enabled == true || !Uri.TryCreate(backend?.BaseUrl, UriKind.Absolute, out var parsed)) return false;
        if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps) return false;
        if (!parsed.IsWellFormedOriginalString() || parsed.Query.Length != 0 || parsed.Fragment.Length != 0) return false;
        address = parsed;
        return true;
    }

    static bool IsOwnBackend(ForwardedIdentitySigningKey service, ForwardedIdentitySigningKey tenant, C.ServiceEndpoint? backend, string endpoint)
    {
        if (!string.Equals(service.Audience, tenant.Audience, StringComparison.Ordinal) ||
            !TryGetBackendAddress(backend, out var backendUri) ||
            !Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri))
        {
            return false;
        }

        // Selection options have no service reference: only the configured backend origin and path scope establish ownership.
        if (!SameOrigin(backendUri, endpointUri)) return false;
        var path = backendUri.AbsolutePath.TrimEnd('/');
        return string.Equals(endpointUri.AbsolutePath, path, StringComparison.Ordinal) || endpointUri.AbsolutePath.StartsWith(path + "/", StringComparison.Ordinal);
    }

    static bool SameOrigin(Uri first, Uri second) =>
        string.Equals(first.Scheme, second.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(first.IdnHost, second.IdnHost, StringComparison.OrdinalIgnoreCase) &&
        first.Port == second.Port &&
        string.Equals(first.UserInfo, second.UserInfo, StringComparison.Ordinal);
}
