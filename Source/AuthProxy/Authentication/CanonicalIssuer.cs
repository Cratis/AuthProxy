// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Normalizes issuer identifiers into the canonical representation used by federated identity assertions.
/// </summary>
/// <remarks>
/// Normalization validates syntax and representation only. It does not authenticate the issuer or establish
/// authority for a value obtained from a principal, request header, or other producer-controlled input.
/// </remarks>
internal static class CanonicalIssuer
{
    /// <summary>
    /// Attempts to validate and normalize an absolute HTTPS issuer, allowing HTTP only for loopback development issuers.
    /// </summary>
    /// <param name="value">The issuer value to validate and normalize.</param>
    /// <param name="normalized">The canonical issuer when validation succeeds; otherwise, an empty string.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is valid and normalized; otherwise, <see langword="false"/>.</returns>
    internal static bool TryNormalize(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value)
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                && !(string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && uri.IsLoopback))
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        var scheme = uri.Scheme.ToLowerInvariant();
        var host = uri.IdnHost.ToLowerInvariant();
        if (host.Contains(':', StringComparison.Ordinal))
        {
            host = $"[{host}]";
        }

        var port = uri.IsDefaultPort ? string.Empty : $":{uri.Port}";
        var path = uri.GetComponents(UriComponents.Path, UriFormat.UriEscaped).TrimEnd('/');
        normalized = $"{scheme}://{host}{port}{(path.Length > 0 ? $"/{path}" : string.Empty)}";
        return normalized.Length <= 2048;
    }
}
