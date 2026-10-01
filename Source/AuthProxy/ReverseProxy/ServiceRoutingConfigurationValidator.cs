// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Validates the host and path-prefix routing of every service at startup.
/// </summary>
/// <remarks>
/// A routing declaration that cannot be honored, or two services that could claim the same request at the same
/// step of <see cref="ServiceRoutes"/>, stop the host with a message naming them. Two services claiming one
/// request would otherwise surface as an ambiguous-match error on that request, or as traffic quietly reaching
/// the wrong service.
/// </remarks>
public class ServiceRoutingConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();
        var declared = new List<(string Name, string? Prefix, HostString[] Hosts)>();

        foreach (var (serviceName, service) in options.Services)
        {
            var hosts = new List<HostString>();
            foreach (var entry in service.Hosts)
            {
                if (ServiceRoutes.TryParseHost(entry, out var host))
                {
                    hosts.Add(host);
                    continue;
                }

                failures.Add($"Service '{serviceName}': Hosts entry '{entry}' is not a host name with an optional port, such as reporting.example.com or reporting.example.com:8443. Wildcards are not supported.");
            }

            var prefix = ValidatePathPrefix(serviceName, service, failures);

            if ((hosts.Count > 0 || prefix is not null) && service.Backend is null && service.Frontend is null)
            {
                failures.Add($"Service '{serviceName}' declares Hosts or a PathPrefix but has no Backend or Frontend to route them to.");
            }

            if (service.StripPathPrefix && string.IsNullOrWhiteSpace(service.PathPrefix))
            {
                failures.Add($"Service '{serviceName}' sets StripPathPrefix but declares no PathPrefix to strip.");
            }

            if (hosts.Count > 0 || prefix is not null)
            {
                declared.Add((serviceName, prefix, [.. hosts]));
            }
        }

        failures.AddRange(Conflicts(declared));

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static string? ValidatePathPrefix(string serviceName, C.Service service, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(service.PathPrefix))
        {
            return null;
        }

        var rejection = AnonymousPathPolicy.Evaluate(service.PathPrefix, out var prefix);
        if (rejection != AnonymousPathRejection.None)
        {
            failures.Add($"Service '{serviceName}': PathPrefix '{service.PathPrefix}' is refused ({rejection}). Declare a rooted path of plain literal segments, such as /reporting, that is not one of the paths AuthProxy reserves for itself.");
            return null;
        }

        if (new PathString(prefix).StartsWithSegments(ServiceRoutes.ApiPathPrefix, StringComparison.OrdinalIgnoreCase))
        {
            failures.Add($"Service '{serviceName}': PathPrefix '{service.PathPrefix}' would take {ServiceRoutes.ApiPathPrefix} from every other service. Choose a prefix outside {ServiceRoutes.ApiPathPrefix}.");
            return null;
        }

        return prefix;
    }

    static IEnumerable<string> Conflicts(List<(string Name, string? Prefix, HostString[] Hosts)> declared)
    {
        for (var i = 0; i < declared.Count; i++)
        {
            for (var j = i + 1; j < declared.Count; j++)
            {
                var (first, second) = (declared[i], declared[j]);
                var sharedHost = first.Hosts.SelectMany(a => second.Hosts.Where(b => ServiceRoutes.Overlap(a, b)).Select(_ => a)).FirstOrDefault();
                var bothOnEveryHost = first.Hosts.Length == 0 && second.Hosts.Length == 0;

                // The same route step only: host+prefix with host+prefix on a shared host, prefix alone with
                // prefix alone, host alone with host alone on a shared host. Across steps, route order decides.
                var conflict = (first.Prefix, second.Prefix) switch
                {
                    ({ } a, { } b) when (bothOnEveryHost || sharedHost.HasValue) && ServiceRoutes.Overlap(a, b) =>
                        $"Services '{first.Name}' and '{second.Name}' declare overlapping path prefixes '{a}' and '{b}'{(sharedHost.HasValue ? $" on host '{sharedHost.Value}'" : string.Empty)}. Path prefixes on the same hosts may not be equal or nested.",
                    (null, null) when sharedHost.HasValue =>
                        $"Services '{first.Name}' and '{second.Name}' both claim host '{sharedHost.Value}'. Give each its own host, or a PathPrefix to tell them apart.",
                    _ => null
                };

                if (conflict is not null)
                {
                    yield return conflict;
                }
            }
        }
    }
}
