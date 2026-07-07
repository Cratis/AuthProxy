// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Resolves which configured service should handle a client-credentials request.
/// </summary>
/// <param name="config">Provides the current AuthProxy configuration.</param>
public class ClientCredentialsServiceResolver(
    IOptionsMonitor<C.AuthProxy> config)
{
    /// <summary>
    /// Tries to resolve the target service for a token request.
    /// </summary>
    /// <param name="serviceName">The requested service name, if provided by the caller.</param>
    /// <param name="service">The resolved service configuration.</param>
    /// <param name="errorDescription">The OAuth error description to return when resolution fails.</param>
    /// <returns><see langword="true"/> if a service was resolved; otherwise <see langword="false"/>.</returns>
    public bool TryResolveForTokenRequest(
        string? serviceName,
        out ConfiguredClientCredentialsService service,
        out string errorDescription)
    {
        var configuredServices = GetConfiguredServices().ToArray();
        if (configuredServices.Length == 0)
        {
            service = default!;
            errorDescription = "No services are configured for client credentials.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(serviceName))
        {
            var namedService = configuredServices.FirstOrDefault(_ => string.Equals(_.Name, serviceName, StringComparison.OrdinalIgnoreCase));
            if (namedService is not null)
            {
                service = namedService;
                errorDescription = string.Empty;
                return true;
            }

            service = default!;
            errorDescription = $"The service '{serviceName}' is not configured for client credentials.";
            return false;
        }

        if (configuredServices.Length == 1)
        {
            service = configuredServices[0];
            errorDescription = string.Empty;
            return true;
        }

        service = default!;
        errorDescription = "Multiple services are configured for client credentials. Specify the 'service' form field.";
        return false;
    }

    /// <summary>
    /// Tries to resolve the target service for an authenticated bearer request.
    /// </summary>
    /// <param name="request">The incoming HTTP request.</param>
    /// <param name="service">The resolved service configuration.</param>
    /// <returns><see langword="true"/> if a service was resolved; otherwise <see langword="false"/>.</returns>
    public bool TryResolveForRequest(HttpRequest request, out ConfiguredClientCredentialsService service)
    {
        var candidates = GetConfiguredServices()
            .Where(_ => request.Path.StartsWithSegments(new PathString(_.RoutePrefix), StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (candidates.Length == 0)
        {
            service = default!;
            return false;
        }

        var requestedService = request.Headers[Headers.ServiceId].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(requestedService))
        {
            requestedService = request.Query["service"].FirstOrDefault();
        }

        if (!string.IsNullOrWhiteSpace(requestedService))
        {
            var namedService = candidates.FirstOrDefault(_ => string.Equals(_.Name, requestedService, StringComparison.OrdinalIgnoreCase));
            if (namedService is not null)
            {
                service = namedService;
                return true;
            }

            service = default!;
            return false;
        }

        if (candidates.Length == 1)
        {
            service = candidates[0];
            return true;
        }

        service = default!;
        return false;
    }

    static Uri? CreateVerificationUri(string baseUrl, string verificationPath)
    {
        if (Uri.TryCreate(verificationPath, UriKind.Absolute, out var absoluteUri))
        {
            return absoluteUri;
        }

        return Uri.TryCreate(new Uri(baseUrl), verificationPath, out var relativeUri)
            ? relativeUri
            : null;
    }

    static string NormalizeRoutePrefix(string routePrefix)
    {
        var normalized = string.IsNullOrWhiteSpace(routePrefix)
            ? "/api"
            : routePrefix.Trim();

        if (!normalized.StartsWith('/'))
        {
            normalized = $"/{normalized}";
        }

        return normalized.Length > 1
            ? normalized.TrimEnd('/')
            : normalized;
    }

    IEnumerable<ConfiguredClientCredentialsService> GetConfiguredServices()
    {
        foreach (var (name, service) in config.CurrentValue.Services)
        {
            if (service.Backend is null || service.ClientCredentials is null)
            {
                continue;
            }

            var routePrefix = NormalizeRoutePrefix(service.ClientCredentials.RoutePrefix);
            var verificationUri = CreateVerificationUri(service.Backend.BaseUrl, service.ClientCredentials.VerificationPath);
            if (verificationUri is null)
            {
                continue;
            }

            yield return new ConfiguredClientCredentialsService(name, routePrefix, verificationUri);
        }
    }
}
