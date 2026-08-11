// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Attestations;

/// <summary>
/// Mints the RS256 JWS assertions AuthProxy signs for its server-to-server protocols.
/// </summary>
/// <remarks>
/// This is the one signing implementation in AuthProxy. It owns the bindings every signed AuthProxy assertion
/// carries — provenance (<c>iss</c> plus the <c>kid</c> header selecting the key), audience (<c>aud</c>),
/// freshness (<c>iat</c>, <c>nbf</c>, <c>exp</c>) and replay resistance (a random 256-bit <c>jti</c>) — and
/// leaves every protocol-specific binding to the caller's claims. Signing never throws on unusable key
/// material; it reports failure so a caller can refuse to send rather than fall back to an unsigned call.
/// </remarks>
public static class AttestationSigner
{
    /// <summary>
    /// Creates a cryptographically random 256-bit opaque value.
    /// </summary>
    /// <returns>A base64url-encoded opaque value.</returns>
    public static string CreateOpaqueValue()
    {
        Span<byte> value = stackalloc byte[32];
        RandomNumberGenerator.Fill(value);
        return Base64UrlEncoder.Encode(value.ToArray());
    }

    /// <summary>
    /// Tries to sign one assertion carrying the supplied protocol claims.
    /// </summary>
    /// <param name="contract">The resolved signing parameters.</param>
    /// <param name="issuedAt">The instant the assertion is issued, from which <c>iat</c>, <c>nbf</c> and <c>exp</c> are derived.</param>
    /// <param name="claims">The protocol claims to bind, extended in place with the generated <c>jti</c>.</param>
    /// <param name="attestation">The compact signed JWS when successful; otherwise an empty string.</param>
    /// <returns><see langword="true"/> when the assertion was signed; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// A <see langword="false"/> result means the configured key material could not be used. It is never a
    /// reason to proceed unsigned — a caller that has been configured to sign must refuse to send instead.
    /// </remarks>
    public static bool TryIssue(
        AttestationSigningContract contract,
        DateTimeOffset issuedAt,
        IDictionary<string, object> claims,
        out string attestation)
    {
        attestation = string.Empty;
        if (!TryCreateSigningCredentials(contract, out var credentials))
        {
            return false;
        }

        claims[JwtRegisteredClaimNames.Jti] = CreateOpaqueValue();

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = contract.Issuer,
            Audience = contract.Audience,
            IssuedAt = issuedAt.UtcDateTime,
            NotBefore = issuedAt.UtcDateTime,
            Expires = issuedAt.Add(contract.Lifetime).UtcDateTime,
            Claims = claims,
            SigningCredentials = credentials,
        };

        attestation = new JsonWebTokenHandler().CreateToken(descriptor);
        return true;
    }

    static bool TryCreateSigningCredentials(AttestationSigningContract contract, out SigningCredentials credentials)
    {
        credentials = default!;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(contract.PrivateKeyPem);
            var securityKey = new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = contract.KeyId };
            credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
            return true;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return false;
        }
    }
}
