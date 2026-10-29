// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the signing configuration for on-behalf sessions.
/// </summary>
/// <remarks>
/// Every call AuthProxy makes to the application about an on-behalf session, and every request it forwards
/// during one, carries a short-lived RS256 JSON Web Token signed with the active key. The application pins the
/// issuer, the audience and the public keys it accepts, and verifies the token before believing anything about
/// who is acting on behalf of whom.
/// </remarks>
public class OnBehalfAttestation
{
    /// <summary>
    /// Gets or sets the issuer (<c language="text">iss</c>) the application pins.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the audience (<c language="text">aud</c>) the application pins.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the identifier of the key that signs. It must name exactly one of <see cref="SigningKeys"/>.
    /// </summary>
    public string ActiveKeyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the signing keys. Keep the outgoing key listed while the application still trusts it, so a key
    /// can be rotated without a gap.
    /// </summary>
    public IList<OnBehalfAttestationSigningKey> SigningKeys { get; set; } = [];

    /// <summary>
    /// Gets or sets how long each signed token is valid. Defaults to sixty seconds; must be between ten and sixty
    /// seconds.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromSeconds(60);
}
