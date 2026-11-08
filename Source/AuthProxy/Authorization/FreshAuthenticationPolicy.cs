// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>Matches authentication-age rules against the selected service's effective path.</summary>
internal static class FreshAuthenticationPolicy
{
    /// <summary>Determines whether the opt-in feature is active.</summary>
    /// <param name="config">The current configuration.</param>
    /// <returns>Whether any service declares rules.</returns>
    internal static bool AnyConfigured(C.AuthProxy config) => config.Services.Values.Any(_ => _.FreshAuthentication is { Count: > 0 });

    /// <summary>Validates path and method syntax using the forwarding-path grammar.</summary>
    /// <param name="rule">The declared rule.</param>
    /// <param name="path">The normalized service-local path.</param>
    /// <param name="methods">The normalized HTTP methods.</param>
    /// <returns>Whether the rule has valid path and method syntax.</returns>
    internal static bool TryNormalize(C.FreshAuthenticationRule rule, out string path, out string[] methods) =>
        ForwardingPathPolicy.Evaluate(new C.ForwardingPathRule { Path = rule.Path, Match = C.ForwardingPathMatch.Exact, Methods = rule.Methods ?? [] }, out path, out methods) == ForwardingPathEntryRejection.None;

    /// <summary>Gets the canonical service-local request path, refusing ambiguous spellings.</summary>
    /// <param name="request">The request.</param>
    /// <param name="effectivePath">The path after optional prefix removal.</param>
    /// <param name="path">The canonical path.</param>
    /// <returns>Whether the request path is unambiguous.</returns>
    internal static bool TryNormalizeRequest(HttpRequest request, PathString effectivePath, out string path)
    {
        var value = effectivePath.Value ?? "/";
        path = value.Length > 1 && value.EndsWith('/') ? value[..^1] : value;
        return ForwardingPathPolicy.IsUnambiguous(request.Path);
    }

    /// <summary>Finds the strictest matching authentication-age rule.</summary>
    /// <param name="service">The selected service.</param>
    /// <param name="path">The canonical service-local path.</param>
    /// <param name="method">The request method.</param>
    /// <returns>The smallest matching age, or null when no rule matches.</returns>
    internal static TimeSpan? MaxAge(C.Service service, string path, string method)
    {
        TimeSpan? result = null;
        foreach (var rule in service.FreshAuthentication ?? [])
        {
            if (!TryNormalize(rule, out var declared, out var methods))
            {
                continue;
            }
            if ((methods.Length == 0 || methods.Contains(method, StringComparer.OrdinalIgnoreCase)
                    || (HttpMethods.IsHead(method) && methods.Contains(HttpMethods.Get, StringComparer.OrdinalIgnoreCase)))
                && (declared == "/" || (rule.Prefix
                    ? new PathString(path).StartsWithSegments(declared, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(path, declared, StringComparison.OrdinalIgnoreCase))))
            {
                result = result is null || rule.MaxAge < result ? rule.MaxAge : result;
            }
        }
        return result;
    }
}
