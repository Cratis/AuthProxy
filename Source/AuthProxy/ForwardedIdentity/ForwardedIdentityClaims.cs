// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// The claims of one forwarded-identity assertion, in the order they are written.
/// </summary>
/// <param name="Issuer">The <c language="text">iss</c> claim: the configured AuthProxy deployment.</param>
/// <param name="Audience">The <c language="text">aud</c> claim: the target service.</param>
/// <param name="IssuedAt">The <c language="text">iat</c> and <c language="text">nbf</c> claims, in seconds since the Unix epoch.</param>
/// <param name="Expires">The <c language="text">exp</c> claim, in seconds since the Unix epoch.</param>
/// <param name="Id">The <c language="text">jti</c> claim: 128 random bits, base64url-encoded.</param>
/// <param name="Method">The <c language="text">htm</c> claim: the outbound request method.</param>
/// <param name="Path">The <c language="text">htp</c> claim: the outbound request path, without the query.</param>
/// <param name="Subject">The <c language="text">sub</c> claim, omitted when the request is anonymous.</param>
/// <param name="Tenant">The <c language="text">tid</c> claim, omitted when the request carries no tenant.</param>
/// <param name="HeaderDigest">The <c language="text">fwh</c> claim: the digest of the bound headers.</param>
record ForwardedIdentityClaims(
    string Issuer,
    string Audience,
    long IssuedAt,
    long Expires,
    string Id,
    string Method,
    string Path,
    string? Subject,
    string? Tenant,
    string HeaderDigest);
