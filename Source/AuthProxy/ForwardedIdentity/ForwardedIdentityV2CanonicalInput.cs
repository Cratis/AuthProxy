// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Text;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Builds the bounded byte-exact Arc v2 canonical input from a final request and trusted context.</summary>
public static class ForwardedIdentityV2CanonicalInput
{
    const string TokenPunctuation = "!#$%&'*+-.^_`|~";
    static readonly string[] _routingHeaders = [Headers.TokenClientId, Headers.TokenScope, Headers.TenantId, Headers.LegacyTenantId, Headers.ServiceId, Headers.LegacyServiceId];

    /// <summary>Builds input only when the final request agrees with the independently supplied trusted evidence.</summary>
    /// <param name="request">The final request immediately before transport.</param>
    /// <param name="context">Verified evidence; never read from inbound identity headers.</param>
    /// <param name="audience">The receiving application's audience.</param>
    /// <param name="keyId">The configured signing key identifier.</param>
    /// <param name="timestamp">The canonical timestamp.</param>
    /// <param name="nonce">The canonical 16-byte base64url nonce.</param>
    /// <param name="canonical">The canonical UTF-8 input.</param>
    /// <returns>Whether the request can be signed.</returns>
    public static bool TryCreate(HttpRequestMessage request, ForwardedIdentityTrustedContext context, string audience, string keyId, string timestamp, string nonce, out byte[] canonical)
    {
        canonical = [];
        if (request.RequestUri is not { IsAbsoluteUri: true } uri || !ForwardedIdentityV2ContextHeaders.Matches(request, context)) return false;
        var headers = request.Headers.NonValidated.Select(header => new KeyValuePair<string, IEnumerable<string>>(header.Key, header.Value));
        if (request.Content is not null)
        {
            headers = headers.Concat(request.Content.Headers.NonValidated.Select(header => new KeyValuePair<string, IEnumerable<string>>(header.Key, header.Value)));
        }
        return string.IsNullOrEmpty(uri.Fragment) && TryCreate(request.Method.Method, uri.PathAndQuery, headers, audience, keyId, timestamp, nonce, context.TenantHeader, out canonical);
    }

    /// <summary>Frames the raw covered snapshot, also used by byte-exact conformance tests.</summary>
    /// <param name="method">The uppercase HTTP token.</param>
    /// <param name="rawTarget">The escaped origin-form request target.</param>
    /// <param name="headers">The complete uncoalesced header snapshot.</param>
    /// <param name="audience">The application slug.</param>
    /// <param name="keyId">The envelope key identifier.</param>
    /// <param name="timestamp">The canonical timestamp.</param>
    /// <param name="nonce">The canonical 16-byte nonce.</param>
    /// <param name="tenantHeader">The receiving host's tenancy header.</param>
    /// <param name="canonical">The resulting canonical bytes.</param>
    /// <returns>Whether the snapshot satisfies the structural contract.</returns>
    internal static bool TryCreate(string method, string rawTarget, IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers, string audience, string keyId, string timestamp, string nonce, string tenantHeader, out byte[] canonical)
    {
        canonical = [];
        if (!ForwardedIdentitySigningKey.IsValidAudience(audience) || !ForwardedIdentitySigningKey.IsValidKeyId(keyId)
            || !ForwardedIdentityV2Envelope.IsTimestamp(timestamp) || !ForwardedIdentityV2Envelope.IsBase64Url(nonce, 16)
            || !IsToken(method) || method.Any(char.IsAsciiLetterLower) || !IsToken(tenantHeader)
            || !TryPath(rawTarget, out var path))
        {
            return false;
        }

        var snapshot = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var header in headers)
        {
            if (!IsCovered(header.Key, tenantHeader)) continue;
            var values = header.Value.ToArray();
            if (!IsToken(header.Key) || values.Length != 1) return false;
            var value = values[0].Trim(' ', '\t');
            if (value.Any(character => character < 32 || character > 126) || !snapshot.TryAdd(header.Key.ToLowerInvariant(), value)) return false;
        }
        if (snapshot.Count > 64) return false;
        foreach (var required in new[] { Headers.Principal, Headers.PrincipalId, Headers.PrincipalName })
        {
            if (!snapshot.TryGetValue(required, out var value) || value.Length == 0) return false;
        }
        var input = new StringBuilder("Cratis.AuthProxy.ForwardedIdentity.v2\n");
        foreach (var field in new[] { audience, keyId, timestamp, nonce, method, path, snapshot.Count.ToString(CultureInfo.InvariantCulture) }) Frame(input, field);
        foreach (var header in snapshot)
        {
            Frame(input, header.Key);
            Frame(input, header.Value);
            if (input.Length > 32768) return false;
        }
        canonical = Encoding.UTF8.GetBytes(input.ToString());
        return canonical.Length <= 32768;
    }

    static void Frame(StringBuilder input, string value) => input.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)).Append(':').Append(value).Append('\n');

    static bool IsCovered(string name, string tenantHeader) => !name.Equals(Headers.ForwardedIdentitySignature, StringComparison.OrdinalIgnoreCase)
        && (name.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase)
            || name.StartsWith(Headers.OnBehalfPrefix, StringComparison.OrdinalIgnoreCase)
            || _routingHeaders.Contains(name, StringComparer.OrdinalIgnoreCase)
            || ForwardedIdentityV2ContextHeaders.Names.Contains(name, StringComparer.OrdinalIgnoreCase)
            || name.Equals(tenantHeader, StringComparison.OrdinalIgnoreCase));

    static bool IsToken(string value) => value.Length > 0 && value.All(character => char.IsAsciiLetterOrDigit(character) || TokenPunctuation.Contains(character, StringComparison.Ordinal));

    static bool TryPath(string target, out string path)
    {
        path = string.Empty;
        if (!target.StartsWith('/') || target.Any(character => character <= 32 || character >= 127 || character == '#')) return false;
        var characters = target.Split('?')[0].ToCharArray();
        for (var index = 0; index < characters.Length; index++)
        {
            if (characters[index] != '%') continue;
            if (index + 2 >= characters.Length || !Uri.IsHexDigit(characters[index + 1]) || !Uri.IsHexDigit(characters[index + 2])) return false;
            characters[++index] = char.ToUpperInvariant(characters[index]);
            characters[++index] = char.ToUpperInvariant(characters[index]);
        }
        path = new string(characters);
        return true;
    }
}
