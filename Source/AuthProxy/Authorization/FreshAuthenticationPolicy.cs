// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Http.Features;
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

    /// <summary>Refuses bearer forwarding when the request requires interactive authentication or is ambiguous.</summary>
    /// <param name="request">The request.</param>
    /// <param name="service">The selected service.</param>
    /// <returns>Whether bearer forwarding must be refused.</returns>
    internal static bool RefusesBearerRequest(HttpRequest request, C.Service service) =>
        service.FreshAuthentication is { Count: > 0 } &&
        (ForwardingPathPolicy.HasMethodOverride(request) ||
         !TryNormalizeRequest(request, request.Path, out var path) ||
         RefusesSafeBody(request, service, path) ||
         MaxAge(service, path, request.Method) is not null);

    /// <summary>Refuses GET or HEAD bodies on rule-matching paths without consuming the request body.</summary>
    /// <param name="request">The request.</param>
    /// <param name="service">The selected service.</param>
    /// <param name="path">The canonical service-local path.</param>
    /// <returns>Whether request framing allows a body on a protected read path.</returns>
    internal static bool RefusesSafeBody(HttpRequest request, C.Service service, string path) =>
        (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method)) &&
        HasBodyFraming(request) &&
        (service.FreshAuthentication ?? []).Any(rule => TryNormalize(rule, out var declared, out _) && MatchesPath(rule, declared, path));

    /// <summary>Finds the strictest matching rule, pooling non-safe methods so backend overrides cannot bypass freshness.</summary>
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
            if (MatchesMethod(methods, method)
                && MatchesPath(rule, declared, path))
            {
                result = result is null || rule.MaxAge < result ? rule.MaxAge : result;
            }
        }
        return result;
    }

    static bool HasBodyFraming(HttpRequest request) =>
        request.HttpContext.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody == true ||
        request.ContentLength > 0 || request.Headers.ContainsKey("Transfer-Encoding");

    static bool MatchesPath(C.FreshAuthenticationRule rule, string declared, string path) =>
        declared == "/" || (rule.Prefix
            ? new PathString(path).StartsWithSegments(declared, StringComparison.OrdinalIgnoreCase)
            : string.Equals(path, declared, StringComparison.OrdinalIgnoreCase));

    static bool MatchesMethod(string[] methods, string method) =>
        methods.Length == 0 || (IsSafe(method)
            ? methods.Contains(method, StringComparer.OrdinalIgnoreCase)
            : methods.Any(declared => !IsSafe(declared)));

    static bool IsSafe(string method) =>
        HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method) || HttpMethods.IsTrace(method);
}
