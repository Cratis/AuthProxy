// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.RegularExpressions;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Produces alternatives to the path already decoded and normalized by the server.
/// </summary>
public static partial class DeniedPathNormalization
{
    [GeneratedRegex("/{2,}", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RepeatedSlashes { get; }

    /// <summary>
    /// Maps remaining encoded separators and backslashes to slashes, then collapses repeated slashes.
    /// Does not decode other characters or resolve dot segments: those are the server's responsibility.
    /// </summary>
    /// <param name="path">The combined Request.PathBase and Request.Path values.</param>
    /// <returns>The alternative path to check alongside the unchanged path.</returns>
    public static string NormalizeSeparators(string path)
    {
        var separators = path.Replace("%2F", "/", StringComparison.OrdinalIgnoreCase)
            .Replace("%5C", "/", StringComparison.OrdinalIgnoreCase)
            .Replace('\\', '/');
        return RepeatedSlashes.Replace(separators, "/");
    }

    /// <summary>
    /// Normalizes separators before resolving dot segments, refusing ambiguous or above-root paths.
    /// </summary>
    /// <param name="path">The combined Request.PathBase and Request.Path values.</param>
    /// <param name="normalized">The normalized alternative, or an empty string on failure.</param>
    /// <returns>Whether the path could be safely normalized.</returns>
    public static bool TryNormalize(string path, out string normalized)
    {
        normalized = string.Empty;
        try
        {
            path = NormalizeSeparators(path);
        }
        catch (RegexMatchTimeoutException)
        {
            // A normalization timeout must fail closed just like an ambiguous path.
            return false;
        }

        if (path.Contains("%2E", StringComparison.OrdinalIgnoreCase)) return false;
        if (path.Length == 0) return true;
        if (!path.StartsWith('/')) return false;

        return TryResolveDotSegments(path, out normalized);
    }

    static bool TryResolveDotSegments(string path, out string normalized)
    {
        normalized = string.Empty;
        var segments = new List<string>();
        foreach (var segment in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryApplySegment(segments, segment)) return false;
        }

        normalized = "/" + string.Join('/', segments);
        if (segments.Count > 0 && HasTrailingSeparator(path)) normalized += "/";
        return true;
    }

    static bool TryApplySegment(List<string> segments, string segment)
    {
        if (segment == ".") return true;
        if (segment != "..")
        {
            segments.Add(segment);
            return true;
        }

        if (segments.Count == 0) return false;
        segments.RemoveAt(segments.Count - 1);
        return true;
    }

    static bool HasTrailingSeparator(string path) =>
        path.EndsWith('/')
        || path.EndsWith("/.", StringComparison.Ordinal)
        || path.EndsWith("/..", StringComparison.Ordinal);
}
