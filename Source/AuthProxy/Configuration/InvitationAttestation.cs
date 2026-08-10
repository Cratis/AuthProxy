// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures signed, two-stage invitation attestations sent from AuthProxy to the invitation authority.
/// </summary>
public class InvitationAttestation
{
    /// <summary>
    /// Gets or sets the issuer written to every invitation attestation.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the audience expected by the invitation authority.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the identifier of the signing key used for new attestations.
    /// </summary>
    public string ActiveKeyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the signing keys available to AuthProxy.
    /// </summary>
    /// <remarks>
    /// Keep the previous key during a rotation until every attestation it signed has expired. The invitation
    /// authority pins the corresponding public keys and selects one by the required JWT <c>kid</c> header.
    /// </remarks>
    public IList<InvitationAttestationSigningKey> SigningKeys { get; set; } = [];

    /// <summary>
    /// Gets or sets the lifetime of a signed attestation. The default and maximum are 60 seconds.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromSeconds(60);
}
