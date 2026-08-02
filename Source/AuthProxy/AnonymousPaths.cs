// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Resolves the anonymous path prefixes declared in <see cref="C.Service.AnonymousPaths"/>.
/// </summary>
/// <remarks>
/// Three components have to agree on what counts as an anonymous path — <c>SelectProviderMiddleware</c>
/// (do not serve the provider-selection page), <c>TenancyMiddleware</c> (do not refuse a caller with no
/// resolvable tenant), and the reverse-proxy route table (do not apply the authenticated-user
/// authorization policy). If one disagreed the path would still be unreachable and the disagreement would
/// be silent, so they all resolve through here.
/// <para>
/// The middlewares match with <see cref="PathString.StartsWithSegments(PathString)"/> while the route
/// table matches an ASP.NET route template built from the same prefix. Those two agree only for a prefix
/// made of plain literal segments, which is what <see cref="TryNormalize"/> enforces: anything else is
/// discarded rather than matched, so a prefix can never mean one thing to a middleware and another to the
/// router.
/// </para>
/// </remarks>
public static class AnonymousPaths
{
    /// <summary>
    /// Characters that either carry meaning in an ASP.NET route template or change how a path is
    /// segmented, and therefore cannot appear in a declared prefix.
    /// </summary>
    static readonly SearchValues<char> _reservedCharacters = SearchValues.Create("{}?#*[]\\% \t\r\n");

    /// <summary>
    /// Gets the usable, de-duplicated anonymous path prefixes across every configured service.
    /// </summary>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The declared anonymous path prefixes.</returns>
    public static IEnumerable<string> All(C.AuthProxy config) =>
        config.Services.Values
            .SelectMany(For)
            .Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the usable, de-duplicated anonymous path prefixes declared by a single service.
    /// </summary>
    /// <param name="service">The service to read.</param>
    /// <returns>The service's anonymous path prefixes.</returns>
    public static IEnumerable<string> For(C.Service service) =>
        Normalize(service.AnonymousPaths).Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Determines whether the given request path is covered by a declared anonymous path prefix.
    /// </summary>
    /// <param name="path">The request path to evaluate.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when the path is anonymous; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// This runs on every request through two middlewares, so it walks the configuration directly and
    /// short-circuits rather than materializing <see cref="All"/>. With nothing declared it returns
    /// immediately without allocating.
    /// </remarks>
    public static bool Matches(PathString path, C.AuthProxy config)
    {
        foreach (var service in config.Services.Values)
        {
            foreach (var candidate in service.AnonymousPaths)
            {
                if (TryNormalize(candidate, out var prefix) && path.StartsWithSegments(prefix))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Normalizes a declared entry into a usable path prefix.
    /// </summary>
    /// <param name="candidate">The declared entry.</param>
    /// <param name="prefix">The normalized prefix when the entry is usable.</param>
    /// <returns><see langword="true"/> when the entry is usable; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Every rejection here is fail-closed — a discarded entry leaves the path authenticated, never the
    /// other way around. The empty entry is the one that matters most:
    /// <c>PathString.StartsWithSegments(string.Empty)</c> is true for every request, so a blank value
    /// would otherwise turn an entire service anonymous. The bare <c>/</c> is rejected for the same
    /// reason. The remaining rejections keep the prefix safe to interpolate into a route template:
    /// <c>/a{x}</c> would become a route <em>parameter</em>, making the router match <c>/aANYTHING/…</c>
    /// where the middlewares match only the literal, and <c>//a</c> or <c>/a/{**b}</c> is not a legal
    /// template at all, so it would fail the proxy's configuration load at startup. The rest are rejected
    /// because a prefix whose meaning depends on encoding cannot be reasoned about from configuration.
    /// </remarks>
    public static bool TryNormalize(string? candidate, out string prefix)
    {
        prefix = string.Empty;

        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        var normalized = candidate.Trim().TrimEnd('/');

        if (normalized.Length < 2
            || normalized[0] != '/'
            || normalized.Contains("//", StringComparison.Ordinal)
            || normalized.AsSpan().IndexOfAny(_reservedCharacters) >= 0)
        {
            return false;
        }

        prefix = normalized;

        return true;
    }

    static IEnumerable<string> Normalize(IEnumerable<string> candidates)
    {
        foreach (var candidate in candidates)
        {
            if (TryNormalize(candidate, out var prefix))
            {
                yield return prefix;
            }
        }
    }
}
