// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures version-pinned Arc forwarded-identity signing for an outbound flow.
/// </summary>
public class ForwardedIdentitySigning
{
    /// <summary>Gets or sets the explicit wire version, either v1 (the default) or v2. No negotiation or fallback occurs.</summary>
    public string Version { get; set; } = "v1";

    /// <summary>Gets or sets strict standard-base64 PKCS#8 DER P-256 private key material for v2 only.</summary>
    public string PrivateKeyPkcs8Base64 { get; set; } = string.Empty;

    /// <summary>Gets or sets the audience expected by the receiving application.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>Gets or sets the identifier of the shared signing key.</summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>Gets or sets the standard-base64 encoded, 32-byte shared secret.</summary>
    public string SecretBase64 { get; set; } = string.Empty;

    /// <inheritdoc/>
    public override string ToString() => $"Audience = {Audience}, KeyId = {KeyId}";
}
