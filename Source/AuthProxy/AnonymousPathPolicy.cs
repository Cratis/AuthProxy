// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;

namespace Cratis.AuthProxy;

/// <summary>
/// Decides whether a declared anonymous path entry is safe to serve without authentication.
/// </summary>
/// <remarks>
/// Declaring a path anonymous is the one setting in AuthProxy that removes authentication from a surface,
/// so the entry itself is attacker-relevant input: whoever writes the configuration may be copying a path
/// from a bug report, a URL, or a template. Every rule here is fail-closed — a refused entry leaves that
/// path authenticated, never the reverse — and the refusal is reported by
/// <c language="text">MicroserviceReverseProxyConfigProvider</c> rather than swallowed.
/// <para>
/// The characters are an allow-list, not a deny-list, which is the whole point: a deny-list has to
/// anticipate every character that means something to one of the two matchers, and the cost of missing one
/// is a prefix that means different things to the middlewares and to the router. The permitted set is RFC
/// 3986 <em>unreserved</em> (<c language="text">A-Z a-z 0-9 - . _ ~</c>) plus the separator, which is every character a
/// path prefix needs and nothing that carries meaning anywhere else. It excludes, by construction rather
/// than by enumeration: <c language="text">%</c> (a prefix whose meaning depends on encoding cannot be reasoned about, and
/// <c language="text">%2e%2e%2f</c> / <c language="text">%2f</c> are the classic traversal and separator smuggling forms), <c language="text">{}*</c> (a
/// route <em>parameter</em> or catch-all, which would make the router match <c language="text">/aANYTHING/…</c> where the
/// middlewares match only the literal), <c language="text">\</c> (a separator to some backends and not to others),
/// <c language="text">?#</c> (they end the path), <c language="text">;</c> (path parameters, which some backends strip and others do not),
/// <c language="text">:</c> and <c language="text">@</c> (authority syntax), control characters and whitespace (log and header injection,
/// and invisible differences between two entries that read identically), and every non-ASCII character
/// (<c language="text">NFC</c> and <c language="text">NFD</c> spellings of the same path compare unequal, so which one is anonymous would
/// depend on how the configuration file was saved).
/// </para>
/// </remarks>
public static class AnonymousPathPolicy
{
    /// <summary>
    /// The characters a declared prefix may contain: RFC 3986 unreserved, plus the segment separator.
    /// </summary>
    static readonly SearchValues<char> _allowedCharacters = SearchValues.Create(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/");

    /// <summary>
    /// The path prefixes AuthProxy answers itself and therefore cannot hand to a service.
    /// </summary>
    static readonly string[] _reservedPrefixes =
    [
        WellKnownPaths.Cratis,
        WellKnownPaths.Pages,
        WellKnownPaths.InvitePathPrefix,
        WellKnownPaths.Registration,
    ];

    /// <summary>
    /// Evaluates a declared entry, producing the normalized prefix or the reason it was refused.
    /// </summary>
    /// <param name="candidate">The entry exactly as declared in configuration.</param>
    /// <param name="prefix">The normalized prefix when the entry is usable; otherwise empty.</param>
    /// <returns><see cref="AnonymousPathRejection.None"/> when the entry is usable; otherwise the reason.</returns>
    public static AnonymousPathRejection Evaluate(string? candidate, out string prefix)
    {
        prefix = string.Empty;

        if (string.IsNullOrWhiteSpace(candidate))
        {
            return AnonymousPathRejection.Empty;
        }

        var normalized = candidate.Trim().TrimEnd('/');

        // Everything that trims away to nothing or to the bare separator is the same failure:
        // PathString.StartsWithSegments(string.Empty) is true for every request, so either would turn an
        // entire service anonymous — the worst outcome this feature can produce.
        if (normalized.Length < 2)
        {
            return AnonymousPathRejection.Root;
        }

        if (normalized[0] != '/')
        {
            return AnonymousPathRejection.NotRooted;
        }

        if (normalized.AsSpan().IndexOfAnyExcept(_allowedCharacters) >= 0)
        {
            return AnonymousPathRejection.DisallowedCharacter;
        }

        var segmentRejection = EvaluateSegments(normalized);
        if (segmentRejection != AnonymousPathRejection.None)
        {
            return segmentRejection;
        }

        if (IsReserved(normalized))
        {
            return AnonymousPathRejection.ProxyOwnedPath;
        }

        prefix = normalized;

        return AnonymousPathRejection.None;
    }

    /// <summary>
    /// Checks the individual segments of an already character-validated prefix.
    /// </summary>
    /// <param name="normalized">The trimmed, rooted prefix.</param>
    /// <returns><see cref="AnonymousPathRejection.None"/> when every segment is usable; otherwise the reason.</returns>
    /// <remarks>
    /// A <c language="text">.</c> or <c language="text">..</c> segment is refused rather than resolved. Resolving it would be the more
    /// forgiving choice and the wrong one: <c language="text">/public/../admin</c> reads as scoped to <c language="text">/public</c> while
    /// meaning <c language="text">/admin</c>, so silently accepting it as <c language="text">/admin</c> would open a path the operator did
    /// not believe they were naming. Refusing keeps a declaration's meaning the same as its spelling.
    /// </remarks>
    static AnonymousPathRejection EvaluateSegments(string normalized)
    {
        foreach (var segment in normalized[1..].Split('/'))
        {
            if (segment.Length == 0)
            {
                return AnonymousPathRejection.EmptySegment;
            }

            if (string.Equals(segment, ".", StringComparison.Ordinal)
                || string.Equals(segment, "..", StringComparison.Ordinal))
            {
                return AnonymousPathRejection.DotSegment;
            }
        }

        return AnonymousPathRejection.None;
    }

    /// <summary>
    /// Determines whether a prefix overlaps a path AuthProxy answers itself.
    /// </summary>
    /// <param name="normalized">The trimmed, rooted prefix.</param>
    /// <returns><see langword="true"/> when the prefix is reserved; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// An anonymous route is emitted at order 0, ahead of every service-selected route, and the three
    /// middlewares stop applying their checks below a declared prefix. Pointing one at AuthProxy's own
    /// namespace therefore does not make an endpoint public — those endpoints already allow anonymous
    /// callers where they are meant to — it takes the endpoint <em>away</em> from AuthProxy: a declared
    /// <c language="text">/.cratis</c> claims the logout, token, tenant-selection and login endpoints for a backend, and a
    /// declared <c language="text">/invite</c> or <c language="text">/register</c> puts the flow middlewares behind a proxied route. The
    /// prefixes are reserved so that cannot be configured by accident.
    /// </remarks>
    static bool IsReserved(string normalized)
    {
        var path = new PathString(normalized);

        foreach (var reserved in _reservedPrefixes)
        {
            if (path.StartsWithSegments(reserved))
            {
                return true;
            }
        }

        // The provider callbacks are a string prefix rather than a segment prefix — the scheme is appended
        // directly, as in /signin-microsoft — so they are matched the same way the pipeline matches them.
        return normalized.StartsWith(WellKnownPaths.SignInPrefix, StringComparison.OrdinalIgnoreCase);
    }
}
