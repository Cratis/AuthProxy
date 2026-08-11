// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents one RSA key available for signing sign-in notifications.
/// </summary>
public class SignInAttestationSigningKey
{
    /// <summary>
    /// Gets or sets the key identifier written to the JWS <c>kid</c> header.
    /// </summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the PEM-encoded RSA private key.
    /// </summary>
    /// <remarks>
    /// Supply this value through a secret provider. AuthProxy never returns or logs it. Publish only the matching
    /// public key to the application that receives sign-in notifications.
    /// </remarks>
    public string PrivateKeyPem { get; set; } = string.Empty;
}
