// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Parses invitation-token metadata without inferring any trust from the response.
/// </summary>
internal static class InvitationTokenMetadataDocument
{
    /// <summary>
    /// Reads a metadata document bound to the configured issuer, audience and origin.
    /// </summary>
    /// <param name="json">The metadata bytes.</param>
    /// <param name="metadataUrl">The configured metadata URL.</param>
    /// <param name="expectedIssuer">The exact configured issuer.</param>
    /// <param name="expectedAudience">The exact configured audience.</param>
    /// <param name="jwksUri">The same-origin JWKS URL on success.</param>
    /// <param name="failure">A rejection reason without response content.</param>
    /// <returns>Whether the document satisfies the invitation-token contract.</returns>
    internal static bool TryParse(ReadOnlySpan<byte> json, Uri metadataUrl, string expectedIssuer, string expectedAudience, out Uri jwksUri, out string failure)
    {
        jwksUri = null!;
        failure = "Invalid invitation-token metadata.";
        try
        {
            using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 8, AllowDuplicateProperties = false });
            var root = document.RootElement;
            if (!MatchesIdentity(root, expectedIssuer, expectedAudience))
            {
                failure = "Metadata issuer or audience does not match configuration.";
                return false;
            }
            if (!SupportsRs256(root))
            {
                failure = "Metadata does not support RS256.";
                return false;
            }
            if (!TryGetJwksUri(root, metadataUrl, out var parsed))
            {
                failure = "Metadata JWKS URL must be an absolute same-origin URL.";
                return false;
            }

            jwksUri = parsed;
            failure = string.Empty;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    static bool MatchesIdentity(JsonElement root, string issuer, string audience) =>
        root.ValueKind == JsonValueKind.Object && Matches(root, "issuer", issuer) && Matches(root, "audience", audience);

    static bool TryGetJwksUri(JsonElement root, Uri metadataUrl, out Uri uri)
    {
        uri = null!;
        if (!root.TryGetProperty("jwks_uri", out var address) || address.ValueKind != JsonValueKind.String)
        {
            return false;
        }
        if (!BearerRouteTable.TryParseAuthorityUri(address.GetString(), out uri, out _))
        {
            return false;
        }
        return Uri.Compare(metadataUrl, uri, UriComponents.SchemeAndServer, UriFormat.UriEscaped, StringComparison.OrdinalIgnoreCase) == 0;
    }

    static bool Matches(JsonElement root, string name, string expected) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && string.Equals(value.GetString(), expected, StringComparison.Ordinal);

    static bool SupportsRs256(JsonElement root)
    {
        if (!root.TryGetProperty("token_signing_alg_values_supported", out var algorithms) || algorithms.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var supported = false;
        foreach (var algorithm in algorithms.EnumerateArray())
        {
            if (algorithm.ValueKind != JsonValueKind.String)
            {
                return false;
            }
            supported |= string.Equals(algorithm.GetString(), "RS256", StringComparison.Ordinal);
        }
        return supported;
    }
}
