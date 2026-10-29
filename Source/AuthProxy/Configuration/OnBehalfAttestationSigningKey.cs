// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents one RSA key AuthProxy can sign on-behalf tokens with.
/// </summary>
public class OnBehalfAttestationSigningKey
{
    /// <summary>
    /// Gets or sets the key identifier written to the token's <c language="text">kid</c> header.
    /// </summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the PEM-encoded RSA private key, at least 2048 bits. Supply it from a secret store, never from a
    /// checked-in file.
    /// </summary>
    public string PrivateKeyPem { get; set; } = string.Empty;
}
