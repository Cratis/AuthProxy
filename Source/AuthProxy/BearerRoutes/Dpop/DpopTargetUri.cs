// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Builds an exact public escaped target without trusting request authority or forwarded headers.</summary>
internal static class DpopTargetUri
{
    /// <summary>Accepts an HTTPS origin without a path, trailing slash, user information, query or fragment.</summary>
    /// <param name="value">The configured origin.</param>
    /// <param name="origin">The canonical trusted authority.</param>
    /// <returns>Whether the origin is valid.</returns>
    internal static bool TryOrigin(string value, out string origin)
    {
        origin = string.Empty;
        if (string.IsNullOrEmpty(value) || value.Any(character => character is <= ' ' or >= '\u007f' or '\\' or '?' or '#')) return false;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !ValidAuthority(uri)) return false;
        var start = value.IndexOf("://", StringComparison.Ordinal);
        if (start < 0 || value.IndexOf('/', start + 3) >= 0) return false;
        origin = uri.GetLeftPart(UriPartial.Authority);
        return true;
    }

    /// <summary>Uses PathBase/Path and an explicit mount mapping, never a caller-selected origin.</summary>
    /// <param name="request">The server request.</param>
    /// <param name="route">The selected route.</param>
    /// <param name="target">The exact expected target, without a query.</param>
    /// <returns>Whether a trustworthy mapping exists.</returns>
    internal static bool TryBuild(HttpRequest request, C.BearerRoute route, out string target)
    {
        target = string.Empty;
        if (route.Dpop is not { } policy || !TryOrigin(policy.PublicOrigin, out var origin)) return false;
        if (!SafeRawTarget(request)) return false;
        var path = PublicPath(request, route);
        if (path is null || !ValidPath(path)) return false;
        target = origin + path;
        return true;
    }

    /// <summary>Compares the exact escaped paths and configured origin; no aliases are repaired.</summary>
    /// <param name="proof">The proof target.</param>
    /// <param name="expected">The trusted target.</param>
    /// <returns>Whether the targets match exactly without query or fragment.</returns>
    internal static bool Matches(string proof, string expected) =>
        !proof.Contains('?', StringComparison.Ordinal) && !proof.Contains('#', StringComparison.Ordinal)
        && string.Equals(proof, expected, StringComparison.Ordinal);

    /// <summary>Rejects ambiguous paths without normalizing escaped path bytes.</summary>
    /// <param name="path">The escaped absolute path.</param>
    /// <returns>Whether the path is unambiguous.</returns>
    internal static bool ValidPath(string path)
    {
        if (path.Length == 0 || path[0] != '/' || path.Contains("//", StringComparison.Ordinal)) return false;
        if (path.Split('/').Any(DotSegment)) return false;
        return ValidEscapes(path);
    }

    static bool ValidAuthority(Uri uri) => uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0 && uri.Host.Length > 0;
    static bool DotSegment(string segment) => string.Equals(segment, ".", StringComparison.Ordinal) || string.Equals(segment, "..", StringComparison.Ordinal);

    static bool SafeRawTarget(HttpRequest request)
    {
        var raw = request.HttpContext.Features.Get<IHttpRequestFeature>()?.RawTarget;
        return string.IsNullOrEmpty(raw) || ValidPath(raw.Split('?', 2)[0]);
    }

    static string? PublicPath(HttpRequest request, C.BearerRoute route)
    {
        if (route.Dpop!.PublicPathPrefix is not { } prefix) return (request.PathBase + request.Path).ToUriComponent();
        if (!ValidPath(prefix) || !request.Path.StartsWithSegments(route.PathPrefix, StringComparison.Ordinal, out var remaining)) return null;
        var path = (prefix == "/" ? string.Empty : prefix.TrimEnd('/')) + remaining.ToUriComponent();
        return path.Length == 0 ? "/" : path;
    }

    static bool ValidEscapes(string path)
    {
        for (var index = 0; index < path.Length; index++)
        {
            var character = path[index];
            if (character is <= ' ' or >= '\u007f' or '\\' or '?' or '#') return false;
            if (character != '%') continue;
            if (!ValidOctet(path, index)) return false;
            index += 2;
        }
        return true;
    }

    static bool ValidOctet(string path, int index) =>
        index + 2 < path.Length && byte.TryParse(path.AsSpan(index + 1, 2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var octet)
        && octet is > 32 and not 127 and not 92 and not 46;
}
