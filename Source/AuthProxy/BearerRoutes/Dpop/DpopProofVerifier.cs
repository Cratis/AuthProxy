// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Verifies one bounded compact RFC 9449 resource-server proof.</summary>
internal static class DpopProofVerifier
{
    /// <summary>The largest compact proof accepted, in ASCII characters.</summary>
    internal const int MaximumProofLength = 4096;

    /// <summary>The exclusive maximum proof age.</summary>
    internal const int MaximumAgeSeconds = 300;

    /// <summary>The largest printable ASCII proof identifier.</summary>
    internal const int MaximumJtiLength = 256;

    /// <summary>Checks the signature, key binding and per-request claims before any replay state is consumed.</summary>
    /// <param name="proof">The compact proof.</param>
    /// <param name="request">The trusted request and access-token evidence.</param>
    /// <returns>The verified fields or fixed refusal reason.</returns>
    internal static DpopProofResult Verify(string proof, DpopProofRequest request)
    {
        if (proof.Length > MaximumProofLength) return DpopProofResult.Invalid("oversized_proof");
        try
        {
            var parts = proof.Split('.');
            if (parts.Length != 3) return DpopProofResult.Invalid("malformed_proof");
            using var header = DpopEncoding.Json(parts[0]);
            using var payload = DpopEncoding.Json(parts[1]);
            if (!ValidHeader(header.RootElement)) return DpopProofResult.Invalid("invalid_header");
            if (DpopEncoding.Text(header.RootElement, "alg") != "ES256") return DpopProofResult.Invalid("invalid_signature");
            var claims = ValidateClaims(payload.RootElement, request);
            if (claims.Status != DpopProofStatus.Valid) return claims;
            if (!DpopPublicKey.Verify(header.RootElement, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), DpopEncoding.Decode(parts[2]), out var thumbprint)) return DpopProofResult.Invalid("invalid_signature");
            if (!DpopEncoding.Equal(thumbprint, request.Jkt)) return DpopProofResult.Invalid("jkt_mismatch");
            return claims with { Jkt = thumbprint };
        }
        catch (Exception exception) when (exception is JsonException or FormatException or CryptographicException or ArgumentException)
        {
            return DpopProofResult.Invalid("malformed_proof");
        }
    }

    static bool ValidHeader(JsonElement header) =>
        DpopEncoding.Text(header, "typ") == "dpop+jwt"
        && !header.TryGetProperty("crit", out _)
        && !header.TryGetProperty("b64", out _)
        && !header.TryGetProperty("x5c", out _)
        && !header.TryGetProperty("jku", out _)
        && !header.TryGetProperty("x5u", out _);

    static DpopProofResult ValidateClaims(JsonElement payload, DpopProofRequest request)
    {
        if (DpopEncoding.Text(payload, "htm") != request.Method) return DpopProofResult.Invalid("htm_mismatch");
        if (!DpopTargetUri.Matches(DpopEncoding.Text(payload, "htu") ?? string.Empty, request.Target)) return DpopProofResult.Invalid("htu_mismatch");
        if (!ValidTime(payload, request.Now)) return DpopProofResult.Invalid("iat_outside_window");
        var jti = DpopEncoding.Text(payload, "jti");
        if (!ValidJti(jti)) return DpopProofResult.Invalid("invalid_jti");
        if (!DpopEncoding.Equal(DpopEncoding.Text(payload, "ath") ?? string.Empty, DpopEncoding.Hash(request.Token))) return DpopProofResult.Invalid("ath_mismatch");
        return new(DpopProofStatus.Valid, "valid", null, jti, DpopEncoding.Text(payload, "nonce"));
    }

    static bool ValidTime(JsonElement payload, long now) =>
        payload.TryGetProperty("iat", out var iat) && iat.ValueKind == JsonValueKind.Number && iat.TryGetInt64(out var seconds)
        && seconds > now - MaximumAgeSeconds && seconds <= now + 30;

    static bool ValidJti(string? jti) => jti is { Length: >= 22 and <= MaximumJtiLength } && jti.All(character => character is >= '!' and <= '~');
}
