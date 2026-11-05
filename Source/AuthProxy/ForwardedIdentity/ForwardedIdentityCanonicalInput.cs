// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Text;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Creates the bounded, length-framed Arc v1 canonical input from a final outbound message.</summary>
internal static class ForwardedIdentityCanonicalInput
{
    /// <summary>Determines whether a header name belongs to the Arc v1 signed set.</summary>
    /// <param name="name">The header name.</param>
    /// <returns>Whether the header is covered.</returns>
    internal static bool IsCovered(string name) =>
        name.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith(Headers.OnBehalfPrefix, StringComparison.OrdinalIgnoreCase) ||
        name.Equals(Headers.TokenClientId, StringComparison.OrdinalIgnoreCase) ||
        name.Equals(Headers.TokenScope, StringComparison.OrdinalIgnoreCase) ||
        name.Equals(Headers.TenantId, StringComparison.OrdinalIgnoreCase) ||
        name.Equals(Headers.LegacyTenantId, StringComparison.OrdinalIgnoreCase) ||
        name.Equals(Headers.ServiceId, StringComparison.OrdinalIgnoreCase) ||
        name.Equals(Headers.LegacyServiceId, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the request carries principal or on-behalf identity material.</summary>
    /// <param name="request">The outbound request.</param>
    /// <returns>Whether an opted-in request requires a proof.</returns>
    internal static bool IsIdentityBearing(HttpRequestMessage request) => HeadersOf(request).Any(header =>
        header.Key.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase) ||
        header.Key.StartsWith(Headers.OnBehalfPrefix, StringComparison.OrdinalIgnoreCase));

    /// <summary>Captures and canonicalizes the final outbound message.</summary>
    /// <param name="request">The final request.</param>
    /// <param name="audience">The configured audience.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="timestamp">The Unix-seconds timestamp.</param>
    /// <param name="nonce">The base64url nonce.</param>
    /// <param name="canonical">The framed canonical UTF-8 bytes.</param>
    /// <param name="refusal">A bounded refusal reason.</param>
    /// <returns>Whether canonicalization succeeded.</returns>
    internal static bool TryCreate(HttpRequestMessage request, string audience, string keyId, string timestamp, string nonce, out byte[] canonical, out ForwardedIdentityRefusal refusal)
    {
        canonical = [];
        refusal = ForwardedIdentityRefusal.None;
        var method = request.Method.Method;
        if (string.IsNullOrEmpty(method) || method.Any(character => !IsToken(character) || char.IsLower(character)))
        {
            refusal = ForwardedIdentityRefusal.InvalidMethod;
            return false;
        }
        if (request.RequestUri is not { IsAbsoluteUri: true } uri)
        {
            refusal = ForwardedIdentityRefusal.NoAbsoluteAddress;
            return false;
        }
        var path = Path(uri.PathAndQuery);
        if (path is null)
        {
            refusal = ForwardedIdentityRefusal.InvalidPath;
            return false;
        }
        if (!TryHeaders(request, out var headers, out refusal)) return false;

        var input = new StringBuilder("Cratis.AuthProxy.ForwardedIdentity.v1\n");
        var byteCount = Encoding.UTF8.GetByteCount("Cratis.AuthProxy.ForwardedIdentity.v1\n");
        foreach (var value in new[] { audience, keyId, timestamp, nonce, method, path, headers.Count.ToString(CultureInfo.InvariantCulture) })
        {
            byteCount += Frame(input, value);
        }
        foreach (var (name, value) in headers.OrderBy(header => header.Key, StringComparer.Ordinal))
        {
            byteCount += Frame(input, name);
            byteCount += Frame(input, value);
            if (byteCount > 32768)
            {
                refusal = ForwardedIdentityRefusal.CanonicalTooLarge;
                return false;
            }
        }
        canonical = Encoding.UTF8.GetBytes(input.ToString());
        return true;
    }

    /// <summary>Extracts the escaped path and uppercases percent-triplet hex without decoding.</summary>
    /// <param name="rawTarget">The escaped origin-form target.</param>
    /// <returns>The canonical path, or null when malformed.</returns>
    internal static string? Path(string rawTarget)
    {
        var path = rawTarget.Split('?', 2)[0].ToCharArray();
        if (path.Length == 0 || path[0] != '/' || path.Any(character => character is <= ' ' or >= (char)127 or '#')) return null;
        for (var index = 0; index < path.Length; index++)
        {
            if (path[index] != '%') continue;
            if (index + 2 >= path.Length || !Uri.IsHexDigit(path[index + 1]) || !Uri.IsHexDigit(path[index + 2])) return null;
            path[++index] = char.ToUpperInvariant(path[index]);
            path[++index] = char.ToUpperInvariant(path[index]);
        }
        return new(path);
    }

    static bool TryHeaders(HttpRequestMessage request, out Dictionary<string, string> headers, out ForwardedIdentityRefusal refusal)
    {
        headers = new(StringComparer.Ordinal);
        refusal = ForwardedIdentityRefusal.None;
        foreach (var header in HeadersOf(request).Where(header => IsCovered(header.Key)))
        {
            var name = header.Key.ToLowerInvariant();
            var values = header.Value.ToArray();
            if (headers.ContainsKey(name) || values.Length != 1)
            {
                refusal = ForwardedIdentityRefusal.RepeatedHeader;
                return false;
            }
            var value = values[0].Trim(' ', '\t');
            if (value.Any(character => character is < ' ' or >= (char)127))
            {
                refusal = ForwardedIdentityRefusal.InvalidHeaderValue;
                return false;
            }
            headers.Add(name, value);
            if (headers.Count > 64)
            {
                refusal = ForwardedIdentityRefusal.TooManyHeaders;
                return false;
            }
        }
        foreach (var required in new[] { Headers.Principal, Headers.PrincipalId, Headers.PrincipalName })
        {
            if (!headers.TryGetValue(required, out var value) || value.Length == 0)
            {
                refusal = ForwardedIdentityRefusal.IncompleteIdentity;
                return false;
            }
        }
        return true;
    }

    static IEnumerable<KeyValuePair<string, IEnumerable<string>>> HeadersOf(HttpRequestMessage request)
    {
        foreach (var header in request.Headers.NonValidated) yield return new(header.Key, header.Value);
        if (request.Content is not null)
        {
            foreach (var header in request.Content.Headers.NonValidated) yield return new(header.Key, header.Value);
        }
    }

    static bool IsToken(char character) => character is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') || "!#$%&'*+-.^_`|~".Contains(character);

    static int Frame(StringBuilder input, string value)
    {
        var byteCount = Encoding.UTF8.GetByteCount(value);
        var length = byteCount.ToString(CultureInfo.InvariantCulture);
        input.Append(length).Append(':').Append(value).Append('\n');
        return length.Length + byteCount + 2;
    }
}
