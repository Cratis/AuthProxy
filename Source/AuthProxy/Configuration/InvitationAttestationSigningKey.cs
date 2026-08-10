// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents one RSA key available for signing invitation attestations.
/// </summary>
public class InvitationAttestationSigningKey
{
    /// <summary>
    /// Gets or sets the key identifier written to the JWT <c>kid</c> header.
    /// </summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the PEM-encoded RSA private key.
    /// </summary>
    /// <remarks>
    /// Supply this value through a secret provider. AuthProxy never returns or logs it. Publish only the matching
    /// public key to the invitation authority.
    /// </remarks>
    public string PrivateKeyPem { get; set; } = string.Empty;
}
