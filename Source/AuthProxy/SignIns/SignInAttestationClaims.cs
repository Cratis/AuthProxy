// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Defines the claims AuthProxy writes to the signed envelope over a sign-in notification.
/// </summary>
/// <remarks>
/// The envelope is a profile of RFC 9449 (DPoP) rather than a scheme of its own: <see cref="HttpMethod"/> and
/// <see cref="HttpUri"/> are the RFC 9449 route claims with the RFC 9449 semantics, and the standard
/// <c>iss</c>, <c>aud</c>, <c>iat</c>, <c>nbf</c>, <c>exp</c> and <c>jti</c> claims carry provenance, audience,
/// time and replay resistance. <see cref="BodyHash"/> is the one AuthProxy extension — RFC 9449 has no body
/// digest — and uses the identical construction to its <c>ath</c> claim.
/// </remarks>
public static class SignInAttestationClaims
{
    /// <summary>
    /// The HTTP method of the request the envelope accompanies, per RFC 9449.
    /// </summary>
    public const string HttpMethod = "htm";

    /// <summary>
    /// The HTTP target URI of the request the envelope accompanies, per RFC 9449 — without query and fragment.
    /// </summary>
    public const string HttpUri = "htu";

    /// <summary>
    /// The base64url-encoded SHA-256 digest of the exact request body bytes the envelope accompanies.
    /// </summary>
    public const string BodyHash = "body_hash";

    /// <summary>
    /// The claim that separates this envelope from every other assertion AuthProxy signs with the same keys.
    /// </summary>
    public const string Purpose = "purpose";

    /// <summary>
    /// The purpose value for a sign-in notification envelope.
    /// </summary>
    public const string NotificationPurpose = "sign-in-notification";
}
