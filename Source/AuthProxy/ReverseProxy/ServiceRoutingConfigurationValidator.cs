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
        List<string> failures = [];
        List<(string Name, string? Prefix, HostString[] Hosts)> declared = [];

        foreach (var (serviceName, service) in options.Services)
        {
            if (ValidateService(serviceName, service, failures) is { } routing)
            {
                declared.Add(routing);
            }
        }

        failures.AddRange(Conflicts(declared));
        failures.AddRange(DefaultServiceFailures(options));

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static (string Name, string? Prefix, HostString[] Hosts)? ValidateService(string serviceName, C.Service service, List<string> failures)
    {
        var hosts = ParseHosts(serviceName, service, failures);
        var prefix = ValidatePathPrefix(serviceName, service, failures);
        var declaresRouting = hosts.Count > 0 || prefix is not null;

        failures.AddRange(RoutingShapeFailures(serviceName, service, declaresRouting));
        failures.AddRange(PassCallerAuthorizationFailures(serviceName, service));

        return declaresRouting ? (serviceName, prefix, [.. hosts]) : null;
    }

    static IEnumerable<string> RoutingShapeFailures(string serviceName, C.Service service, bool declaresRouting)
    {
        if (declaresRouting && HasNoTarget(service))
        {
            yield return $"Service '{serviceName}' declares Hosts or a PathPrefix but has no Backend or Frontend to route them to.";
        }

        if (service.StripPathPrefix && string.IsNullOrWhiteSpace(service.PathPrefix))
        {
            yield return $"Service '{serviceName}' sets StripPathPrefix but declares no PathPrefix to strip.";
        }
    }

    static bool HasNoTarget(C.Service service) => service.Backend is null && service.Frontend is null;

    static List<HostString> ParseHosts(string serviceName, C.Service service, List<string> failures)
    {
        List<HostString> hosts = [];
        foreach (var entry in service.Hosts)
        {
            if (ServiceRoutes.TryParseHost(entry, out var host))
            {
                hosts.Add(host);
                continue;
            }

            failures.Add($"Service '{serviceName}': Hosts entry '{entry}' is not a host name with an optional port, such as reporting.example.com or reporting.example.com:8443. Wildcards are not supported.");
        }

        return hosts;
    }

    static IEnumerable<string> PassCallerAuthorizationFailures(string serviceName, C.Service service)
    {
        var anonymous = AnonymousPaths.For(service).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in AnonymousPaths.EvaluatePassCallerAuthorization(service))
        {
            if (!entry.IsUsable)
            {
                yield return $"Service '{serviceName}': PassCallerAuthorizationPaths entry '{entry.DeclaredForDisplay}' is refused ({entry.Rejection}).";
            }
            else if (!anonymous.Contains(entry.Prefix))
            {
                yield return $"Service '{serviceName}': PassCallerAuthorizationPaths entry '{entry.DeclaredForDisplay}' is not listed in AnonymousPaths. The caller's Authorization header can be forwarded only on a path that is anonymous to AuthProxy.";
            }
            else if (service.CallerAuthorizationHeader == C.CallerAuthorizationHeaderForwarding.Strip)
            {
                yield return $"Service '{serviceName}': PassCallerAuthorizationPaths entry '{entry.DeclaredForDisplay}' contradicts CallerAuthorizationHeader Strip.";
            }
        }
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
                var conflict = ConflictBetween(declared[i], declared[j]);
                if (conflict is not null)
                {
                    yield return conflict;
                }
            }
        }
    }

    static string? ConflictBetween((string Name, string? Prefix, HostString[] Hosts) first, (string Name, string? Prefix, HostString[] Hosts) second)
    {
        var sharedHost = first.Hosts.SelectMany(a => second.Hosts.Where(b => ServiceRoutes.Overlap(a, b)).Select(_ => a)).FirstOrDefault();
        var bothOnEveryHost = first.Hosts.Length == 0 && second.Hosts.Length == 0;

        // The same route step only: host+prefix with host+prefix on a shared host, prefix alone with
        // prefix alone, host alone with host alone on a shared host. Across steps, route order decides.
        return (first.Prefix, second.Prefix) switch
        {
            ({ } a, { } b) when (bothOnEveryHost || sharedHost.HasValue) && ServiceRoutes.Overlap(a, b) =>
                $"Services '{first.Name}' and '{second.Name}' declare overlapping path prefixes '{a}' and '{b}'{(sharedHost.HasValue ? $" on host '{sharedHost.Value}'" : string.Empty)}. Path prefixes on the same hosts may not be equal or nested.",
            (null, null) when sharedHost.HasValue =>
                $"Services '{first.Name}' and '{second.Name}' both claim host '{sharedHost.Value}'. Give each its own host, or a PathPrefix to tell them apart.",
            _ => null
        };
    }

    static IEnumerable<string> DefaultServiceFailures(C.AuthProxy options)
    {
        var defaults = options.Services.Where(_ => _.Value.Default).Select(_ => _.Key).ToArray();
        if (defaults.Length > 1)
        {
            yield return $"Services {string.Join(", ", defaults.Select(_ => $"'{_}'"))} all set Default; only one service can be reached through the catch-all routes.";
        }

        foreach (var serviceName in defaults.Where(_ => options.Services[_].Hosts.Count > 0 || !string.IsNullOrWhiteSpace(options.Services[_].PathPrefix)))
        {
            yield return $"Service '{serviceName}' sets Default but declares Hosts or a PathPrefix; the default service is the one reached where no host or prefix matches, so it declares neither.";
        }
    }
}
