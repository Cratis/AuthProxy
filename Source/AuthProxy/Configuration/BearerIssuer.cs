// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents an authorization server whose access tokens a <see cref="BearerRoute"/> accepts.
/// </summary>
/// <remarks>
/// AuthProxy only relies on the issuer here — it never issues these tokens. The signing keys are read from the
/// issuer's published metadata (RFC 8414, or OpenID Connect discovery) and its JWKS, cached, and refreshed when a
/// token names a key the cache does not know, so key rotation at the issuer is honored without a restart.
/// </remarks>
public class BearerIssuer
{
    /// <summary>
    /// The access-token media types accepted when <see cref="TokenTypes"/> is left unset: the RFC 9068 JWT access
    /// token profile's <c language="text">at+jwt</c>, in its short and its full form.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultTokenTypes = ["at+jwt", "application/at+jwt"];

    /// <summary>
    /// Gets or sets the issuer identifier. A token is accepted only when its <c language="text">iss</c> claim is exactly
    /// this value, and the issuer's published metadata must name exactly this value too.
    /// </summary>
    /// <remarks>
    /// An absolute HTTPS URI without query, fragment or user information. Plain HTTP is accepted only for a
    /// loopback development issuer.
    /// </remarks>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the metadata document address. Leave unset to use the RFC 8414 address derived from
    /// <see cref="Issuer"/>: <c language="text">/.well-known/oauth-authorization-server</c> inserted between the issuer's
    /// host and path.
    /// </summary>
    public string? MetadataAddress { get; set; }

    /// <summary>
    /// Gets or sets the JWT <c language="text">typ</c> header values accepted from this issuer. Leave unset to accept the
    /// RFC 9068 access-token types in <see cref="DefaultTokenTypes"/> only, which keeps an ID token or any other
    /// JWT the issuer signs from being presented as an access token.
    /// </summary>
    public IList<string> TokenTypes { get; set; } = [];
}
