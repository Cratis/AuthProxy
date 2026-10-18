// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures signed forwarding: an ES256 assertion AuthProxy attaches to every request it forwards to a service,
/// so a backend can verify that the identity and tenant headers it receives were written by AuthProxy.
/// </summary>
/// <remarks>
/// Leave the section unset, the default, and requests are forwarded unsigned exactly as before. Once it is set,
/// AuthProxy never forwards a request unsigned: a request it cannot sign is answered with <c language="text">502</c>
/// and never reaches the backend. Keys are read at startup; changing them requires a restart.
/// </remarks>
public class ForwardingAttestation
{
    /// <summary>
    /// The shortest lifetime an assertion may be configured with.
    /// </summary>
    public static readonly TimeSpan MinimumLifetime = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The longest lifetime an assertion may be configured with.
    /// </summary>
    public static readonly TimeSpan MaximumLifetime = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Gets or sets the issuer written to every assertion. The verifying backend must expect the same value.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the identifier of the signing key used for new assertions.
    /// </summary>
    public string ActiveKeyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the signing keys available to AuthProxy.
    /// </summary>
    /// <remarks>
    /// Each is an EC P-256 private key. A verifying backend pins the matching public keys and selects one by the
    /// <c language="text">kid</c> header. During a rotation, publish the new public key to every backend first,
    /// then add the new private key here and switch <see cref="ActiveKeyId"/>.
    /// </remarks>
    public IList<ForwardingAttestationSigningKey> SigningKeys { get; set; } = [];

    /// <summary>
    /// Gets or sets the lifetime of an assertion. The default is 30 seconds; it must be between 10 and 60 seconds.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromSeconds(30);
}
