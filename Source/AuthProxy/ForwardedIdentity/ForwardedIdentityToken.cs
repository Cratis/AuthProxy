// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Buffers.Text;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// The wire format of the forwarded-identity assertion: the bound header canonicalization, the header digest and
/// the exact JSON of the JWS segments.
/// </summary>
/// <remarks>
/// A verifier in another repository implements the same format from the same text and the same golden vectors,
/// so the JSON is written by hand with a fixed member order and no whitespace rather than by a serializer that
/// could reorder or pad it.
/// </remarks>
static class ForwardedIdentityToken
{
    /// <summary>
    /// The JWS <c language="text">alg</c> header value.
    /// </summary>
    internal const string Algorithm = "ES256";

    /// <summary>
    /// The JWS <c language="text">typ</c> header value.
    /// </summary>
    internal const string Type = "cratis-fwd+jwt";

    /// <summary>
    /// The headers covered by the <c language="text">fwh</c> digest, in digest order and in the lowercase form written
    /// into it.
    /// </summary>
    internal static readonly string[] BoundHeaders =
    [
        Headers.Principal,
        Headers.PrincipalId,
        Headers.PrincipalName,
        Headers.PrincipalNameExtended,
        Headers.TenantId,
        "tenant-id",
        Headers.TokenClientId,
        Headers.TokenScope
    ];

    static readonly JsonWriterOptions _writerOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false
    };

    /// <summary>
    /// Builds the canonical string of the bound headers a request carries.
    /// </summary>
    /// <param name="headers">The outbound request headers, as they will be sent.</param>
    /// <param name="canonical">The canonical string: <c language="text">name:value\n</c> per present header, in digest order.</param>
    /// <param name="subject">The value of <see cref="Headers.PrincipalId"/>, when present.</param>
    /// <param name="tenant">The value of <see cref="Headers.TenantId"/>, when present.</param>
    /// <returns><see langword="false"/> when a bound header occurs more than once or carries a line break.</returns>
    /// <remarks>
    /// A value is taken as it travels, with the optional whitespace around it removed as an HTTP recipient does
    /// (RFC 9110 §5.5), so the digest matches what the backend reads.
    /// </remarks>
    internal static bool TryCanonicalize(HttpRequestHeaders headers, out string canonical, out string? subject, out string? tenant)
    {
        var builder = new StringBuilder();
        subject = null;
        tenant = null;
        canonical = string.Empty;

        foreach (var name in BoundHeaders)
        {
            if (!headers.NonValidated.TryGetValues(name, out var values))
            {
                continue;
            }

            if (values.Count != 1)
            {
                return false;
            }

            var value = values.ToString().Trim(' ', '\t');
            if (value.Contains('\r') || value.Contains('\n'))
            {
                return false;
            }

            builder.Append(name).Append(':').Append(value).Append('\n');
            if (string.Equals(name, Headers.PrincipalId, StringComparison.Ordinal))
            {
                subject = value;
            }
            else if (string.Equals(name, Headers.TenantId, StringComparison.Ordinal))
            {
                tenant = value;
            }
        }

        canonical = builder.ToString();
        return true;
    }

    /// <summary>
    /// Computes the <c language="text">fwh</c> digest of a canonical header string.
    /// </summary>
    /// <param name="canonical">The canonical header string.</param>
    /// <returns>The base64url-encoded SHA-256 of the UTF-8 canonical string.</returns>
    internal static string Digest(string canonical) => Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));

    /// <summary>
    /// Builds the JWS signing input: the encoded protected header, a period, and the encoded payload.
    /// </summary>
    /// <param name="keyId">The identifier of the signing key.</param>
    /// <param name="claims">The claims to sign.</param>
    /// <returns>The signing input.</returns>
    internal static string SigningInput(string keyId, ForwardedIdentityClaims claims) =>
        $"{Base64Url.EncodeToString(ProtectedHeader(keyId))}.{Base64Url.EncodeToString(Payload(claims))}";

    /// <summary>
    /// Signs a signing input and completes the compact JWS.
    /// </summary>
    /// <param name="signingInput">The signing input.</param>
    /// <param name="key">The EC P-256 private key.</param>
    /// <returns>The compact JWS.</returns>
    internal static string Complete(string signingInput, ECDsa key)
    {
        var signature = key.SignData(
            Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>
    /// Creates a fresh 128-bit assertion identifier.
    /// </summary>
    /// <returns>The base64url-encoded identifier.</returns>
    internal static string CreateId()
    {
        Span<byte> id = stackalloc byte[16];
        RandomNumberGenerator.Fill(id);
        return Base64Url.EncodeToString(id);
    }

    static byte[] ProtectedHeader(string keyId) => Write(writer =>
    {
        writer.WriteString("alg", Algorithm);
        writer.WriteString("typ", Type);
        writer.WriteString("kid", keyId);
    });

    static byte[] Payload(ForwardedIdentityClaims claims) => Write(writer =>
    {
        writer.WriteString("iss", claims.Issuer);
        writer.WriteString("aud", claims.Audience);
        writer.WriteNumber("iat", claims.IssuedAt);
        writer.WriteNumber("nbf", claims.IssuedAt);
        writer.WriteNumber("exp", claims.Expires);
        writer.WriteString("jti", claims.Id);
        writer.WriteString("htm", claims.Method);
        writer.WriteString("htp", claims.Path);
        if (claims.Subject is not null)
        {
            writer.WriteString("sub", claims.Subject);
        }

        if (claims.Tenant is not null)
        {
            writer.WriteString("tid", claims.Tenant);
        }

        writer.WriteString("fwh", claims.HeaderDigest);
    });

    static byte[] Write(Action<Utf8JsonWriter> members)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, _writerOptions))
        {
            writer.WriteStartObject();
            members(writer);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }
}
