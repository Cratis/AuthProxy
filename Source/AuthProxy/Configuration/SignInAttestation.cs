// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures the signed envelope AuthProxy sends over every sign-in notification.
/// </summary>
/// <remarks>
/// <para>
/// Leave this section unset — the default — and sign-in notifications are posted exactly as they always have
/// been: an unsigned JSON body with no <c>Authorization</c> header. Nothing about an existing deployment
/// changes on upgrade.
/// </para>
/// <para>
/// Set it and AuthProxy signs a short-lived RS256 JWS over each notification and sends it as
/// <c>Authorization: Bearer</c>. The envelope binds six facts: provenance (<c>iss</c> plus the <c>kid</c>
/// header), audience (<c>aud</c>), route (<c>htm</c> and <c>htu</c>, per RFC 9449), body (<c>body_hash</c>,
/// over the exact bytes posted), time (<c>iat</c>, <c>nbf</c>, <c>exp</c>) and replay (a random <c>jti</c>).
/// Once configured, AuthProxy never falls back to an unsigned notification: if the envelope cannot be signed,
/// nothing is posted.
/// </para>
/// <para>
/// AuthProxy publishes no JWKS document, so the receiving application pins the matching public key by its own
/// configuration and selects it by the required <c>kid</c> header — the same way the invitation authority
/// consumes <see cref="InvitationAttestation"/>.
/// </para>
/// </remarks>
public class SignInAttestation
{
    /// <summary>
    /// Gets or sets the issuer written to every sign-in notification envelope.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the audience expected by the application receiving the notification.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the identifier of the signing key used for new envelopes.
    /// </summary>
    public string ActiveKeyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the signing keys available to AuthProxy.
    /// </summary>
    /// <remarks>
    /// Keep the previous key during a rotation until every envelope it signed has expired. The receiving
    /// application pins the corresponding public keys and selects one by the required JWS <c>kid</c> header.
    /// </remarks>
    public IList<SignInAttestationSigningKey> SigningKeys { get; set; } = [];

    /// <summary>
    /// Gets or sets the lifetime of a signed envelope. The default and maximum are 60 seconds.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromSeconds(60);
}
