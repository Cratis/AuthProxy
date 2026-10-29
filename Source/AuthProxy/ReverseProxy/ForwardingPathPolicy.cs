// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Runtime.CompilerServices;
using Cratis.AuthProxy.BearerRoutes;
using Microsoft.AspNetCore.Http.Features;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>Evaluates service-relative forwarding rules without changing routing or authentication.</summary>
public static class ForwardingPathPolicy
{
    static readonly ConditionalWeakTable<C.Service, CompiledPolicy> _policies = new();
    static readonly SearchValues<char> _literalPathCharacters = SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/");
    static readonly SearchValues<char> _methodTokenCharacters = SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~");
    static readonly string[] _overrideHeaders = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"];

    /// <summary>Gets whether a service declares either list of forwarding rules.</summary>
    /// <param name="service">The service.</param>
    /// <returns>Whether a forwarding policy is configured.</returns>
    public static bool IsConfigured(C.Service service) => service.ForwardedPaths.Count > 0 || service.DeniedPaths.Count > 0;

    /// <summary>Gets whether any service declares a forwarding policy.</summary>
    /// <param name="config">The configuration.</param>
    /// <returns>Whether any service declares forwarding rules.</returns>
    public static bool AnyConfigured(C.AuthProxy config) => config.Services.Values.Any(IsConfigured);

    /// <summary>Validates and normalizes a rule independently of authentication paths.</summary>
    /// <param name="entry">The rule.</param>
    /// <param name="normalizedPath">The normalized literal path.</param>
    /// <param name="normalizedMethods">Uppercase method tokens.</param>
    /// <returns>The entry rejection reason.</returns>
    public static ForwardingPathEntryRejection Evaluate(C.ForwardingPathRule entry, out string normalizedPath, out string[] normalizedMethods)
    {
        normalizedPath = string.Empty;
        normalizedMethods = [];
        var rejection = ValidateEntry(entry);
        if (rejection == ForwardingPathEntryRejection.None)
        {
            normalizedPath = Normalize(entry.Path).Value!;
            normalizedMethods = entry.Methods.Select(method => method.ToUpperInvariant()).ToArray();
        }
        return rejection;
    }

    /// <summary>Gets the path after YARP's optional prefix removal, using root for an empty remainder.</summary>
    /// <param name="path">The request path without its query and path base.</param>
    /// <param name="strippedPrefix">The prefix recorded on the selected route.</param>
    /// <returns>The service-relative path.</returns>
    public static PathString EffectivePath(PathString path, string? strippedPrefix)
    {
        if (!string.IsNullOrEmpty(strippedPrefix) && path.StartsWithSegments(new PathString(strippedPrefix), out var remaining))
        {
            path = remaining;
        }
        return path.HasValue ? path : new PathString("/");
    }

    /// <summary>Gets whether a decoded request path can be matched without further normalization.</summary>
    /// <param name="path">The decoded path, not the query or raw target.</param>
    /// <returns>Whether the path is unambiguous.</returns>
    public static bool IsUnambiguous(PathString path) => BearerRouteTable.IsUnambiguous(path)
        && !(path.Value ?? string.Empty).Any(character => char.IsControl(character) || character is '?' or '#');

    /// <summary>Evaluates a request against the selected service's compiled forwarding policy.</summary>
    /// <param name="request">The request.</param>
    /// <param name="service">The service selected for forwarding.</param>
    /// <param name="effectivePath">The path after optional prefix removal.</param>
    /// <returns>The forwarding refusal, or <see cref="ForwardingPathRefusal.None"/>.</returns>
    public static ForwardingPathRefusal Evaluate(HttpRequest request, C.Service service, PathString effectivePath)
    {
        if (!IsConfigured(service)) return ForwardingPathRefusal.None;
        if (!IsUnambiguous(request.Path)) return ForwardingPathRefusal.NonCanonicalPath;
        if (_overrideHeaders.Any(request.Headers.ContainsKey)) return ForwardingPathRefusal.MethodOverride;
        var method = request.HttpContext.Features.Get<IHttpExtendedConnectFeature>()?.IsExtendedConnect == true ? HttpMethods.Get : request.Method;
        return Decide(_policies.GetValue(service, Compile), Normalize(effectivePath), method);
    }

    static ForwardingPathRefusal Decide(CompiledPolicy policy, PathString path, string method)
    {
        if (!policy.Valid) return ForwardingPathRefusal.NotAllowed;
        if (policy.Denied.Any(rule => Matches(rule, path, method))) return ForwardingPathRefusal.Denied;
        return policy.Allowed.Length == 0 || policy.Allowed.Any(rule => Matches(rule, path, method)) ? ForwardingPathRefusal.None : ForwardingPathRefusal.NotAllowed;
    }

    static ForwardingPathEntryRejection ValidateEntry(C.ForwardingPathRule entry)
    {
        var rejection = ValidatePath(entry.Path);
        if (rejection != ForwardingPathEntryRejection.None) return rejection;
        if (!Enum.IsDefined(entry.Match)) return ForwardingPathEntryRejection.InvalidMatch;
        if (entry.Path == "/" && entry.Match == C.ForwardingPathMatch.Prefix) return ForwardingPathEntryRejection.RootPrefix;
        return entry.Methods.Any(method => string.IsNullOrEmpty(method) || method.AsSpan().ContainsAnyExcept(_methodTokenCharacters)) ? ForwardingPathEntryRejection.InvalidMethod : ForwardingPathEntryRejection.None;
    }

    static ForwardingPathEntryRejection ValidatePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return ForwardingPathEntryRejection.Empty;
        if (path[0] != '/') return ForwardingPathEntryRejection.NotRooted;
        if (path.Any(char.IsWhiteSpace)) return ForwardingPathEntryRejection.Whitespace;
        if (path.AsSpan().ContainsAnyExcept(_literalPathCharacters)) return ForwardingPathEntryRejection.DisallowedCharacter;
        if (path.Contains("//", StringComparison.Ordinal)) return ForwardingPathEntryRejection.EmptySegment;
        return path.Split('/').Any(segment => string.Equals(segment, ".", StringComparison.Ordinal) || string.Equals(segment, "..", StringComparison.Ordinal)) ? ForwardingPathEntryRejection.DotSegment : ForwardingPathEntryRejection.None;
    }

    static PathString Normalize(PathString path)
    {
        var value = path.Value ?? "/";
        return !path.HasValue ? new PathString("/") : value.Length > 1 && value.EndsWith('/') ? new PathString(value[..^1]) : path;
    }

    static bool Matches(CompiledRule rule, PathString path, string method) => MatchesMethod(rule, method)
        && (rule.Match == C.ForwardingPathMatch.Exact
            ? path.Equals(rule.Path, StringComparison.OrdinalIgnoreCase)
            : path.StartsWithSegments(rule.Path, StringComparison.OrdinalIgnoreCase));

    static bool MatchesMethod(CompiledRule rule, string method) => rule.Methods.Length == 0 || rule.Methods.Contains(method, StringComparer.OrdinalIgnoreCase)
        || (HttpMethods.IsHead(method) && rule.Methods.Contains(HttpMethods.Get, StringComparer.OrdinalIgnoreCase));

    static CompiledPolicy Compile(C.Service service)
    {
        var allowed = Compile(service.ForwardedPaths);
        var denied = Compile(service.DeniedPaths);
        return new(allowed, denied, allowed.Length == service.ForwardedPaths.Count && denied.Length == service.DeniedPaths.Count);
    }

    static CompiledRule[] Compile(IList<C.ForwardingPathRule> entries) => entries
        .Select(entry => Evaluate(entry, out var path, out var methods) == ForwardingPathEntryRejection.None ? new CompiledRule(path, entry.Match, methods) : null)
        .OfType<CompiledRule>().ToArray();

    sealed record CompiledRule(PathString Path, C.ForwardingPathMatch Match, string[] Methods);
    sealed record CompiledPolicy(CompiledRule[] Allowed, CompiledRule[] Denied, bool Valid);
}
