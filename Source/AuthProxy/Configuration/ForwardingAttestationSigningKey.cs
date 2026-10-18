// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents one EC P-256 key available for signing forwarded-identity assertions.
/// </summary>
public class ForwardingAttestationSigningKey
{
    /// <summary>
    /// Gets or sets the key identifier written to the JWS <c language="text">kid</c> header.
    /// </summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the PEM-encoded EC P-256 private key.
    /// </summary>
    /// <remarks>
    /// Supply this value through a secret provider. AuthProxy never returns or logs it. Publish only the matching
    /// public key to the verifying backends.
    /// </remarks>
    public string PrivateKeyPem { get; set; } = string.Empty;

    /// <inheritdoc/>
    /// <remarks>
    /// The private key is never part of the text, so logging a key cannot leak it.
    /// </remarks>
    public override string ToString() => $"{nameof(ForwardingAttestationSigningKey)} {{ {nameof(KeyId)} = {KeyId} }}";
}
