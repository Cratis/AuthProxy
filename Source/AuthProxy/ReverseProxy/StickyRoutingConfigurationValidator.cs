// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Refuses a configuration stating sticky routing where it cannot apply, or with values the proxy cannot honor.
/// </summary>
/// <remarks>
/// Sticky routing is a Backend-only setting. Placement is checked whether or not it is enabled; the values are
/// only checked when it is enabled.
/// </remarks>
public sealed partial class StickyRoutingConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    [GeneratedRegex("^[a-z0-9][a-z0-9._-]*$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex CookieSafeServiceName { get; }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();

        foreach (var (serviceName, service) in options.Services)
        {
            var prefix = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.Services)}:{serviceName}";
            CheckPlacement($"{prefix}:{nameof(C.Service.Frontend)}", "Frontend", service.Frontend, failures);
            CheckPlacement($"{prefix}:{nameof(C.Service.Registration)}", "Registration", service.Registration, failures);
            CheckBackend(prefix, serviceName, service.Backend, failures);
        }

        if (options.Invite?.Lobby is { } lobby)
        {
            var prefix = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.Invite)}:{nameof(C.Invite.Lobby)}";
            foreach (var (endpointName, endpoint) in new[]
            {
                (nameof(C.Service.Backend), lobby.Backend),
                (nameof(C.Service.Frontend), lobby.Frontend),
                (nameof(C.Service.Registration), lobby.Registration),
            })
            {
                if (endpoint?.StickyRouting is not null)
                {
                    failures.Add($"{prefix}:{endpointName}:{nameof(C.ServiceEndpoint.StickyRouting)} is not supported. Invite:Lobby does not create a proxied backend cluster, so there are no replicas to pin to. Remove this setting and configure the proxied service under Services instead.");
                }
            }
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }

    static void CheckPlacement(string key, string endpointName, C.ServiceEndpoint? endpoint, List<string> failures)
    {
        if (endpoint?.StickyRouting is not null)
        {
            failures.Add($"{key}:{nameof(C.ServiceEndpoint.StickyRouting)} is not supported. StickyRouting only applies to Backend endpoints, not {endpointName}. Remove this setting.");
        }
    }

    static void CheckBackend(string servicePrefix, string serviceName, C.ServiceEndpoint? backend, List<string> failures)
    {
        if (backend?.StickyRouting is not { Enabled: true } sticky)
        {
            return;
        }

        var key = $"{servicePrefix}:{nameof(C.Service.Backend)}:{nameof(C.ServiceEndpoint.StickyRouting)}";

        var host = string.IsNullOrWhiteSpace(sticky.ReplicaHost)
            ? Uri.TryCreate(backend.BaseUrl, UriKind.Absolute, out var baseUrl) ? baseUrl.IdnHost : string.Empty
            : sticky.ReplicaHost;
        if (host.Length == 0 || host != host.Trim() || Uri.CheckHostName(host) != UriHostNameType.Dns)
        {
            failures.Add(string.IsNullOrWhiteSpace(sticky.ReplicaHost)
                ? $"{key}:{nameof(C.StickyRouting.ReplicaHost)} is not stated and the host of {servicePrefix}:{nameof(C.Service.Backend)}:{nameof(C.ServiceEndpoint.BaseUrl)} is not a DNS name, so there is nothing to discover replicas through. State a DNS host name, for example 'core-headless.studio.svc.cluster.local'."
                : $"{key}:{nameof(C.StickyRouting.ReplicaHost)} is '{sticky.ReplicaHost}', which is not a DNS host name. State only the host name, without a scheme, port, path or IP address, for example 'core-headless.studio.svc.cluster.local'.");
        }

        if (sticky.RefreshInterval < C.StickyRouting.MinimumRefreshInterval || sticky.RefreshInterval > C.StickyRouting.MaximumRefreshInterval)
        {
            failures.Add($"{key}:{nameof(C.StickyRouting.RefreshInterval)} is '{sticky.RefreshInterval}', which is outside the supported range of {C.StickyRouting.MinimumRefreshInterval} to {C.StickyRouting.MaximumRefreshInterval}. Leave the setting unset for the default of {C.StickyRouting.DefaultRefreshInterval}.");
        }

        if (!CookieSafeServiceName.IsMatch(serviceName.ToLowerInvariant()))
        {
            failures.Add($"{servicePrefix} is a service name that cannot name a cookie, and sticky routing names its affinity cookie after the service. Use only letters, digits, '.', '_' and '-' in the service name, starting with a letter or digit.");
        }
    }
}
