// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures Arc v1 forwarded-identity signing for an outbound flow.
/// </summary>
public class ForwardedIdentitySigning
{
    /// <summary>Gets or sets the audience expected by the receiving application.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>Gets or sets the identifier of the shared signing key.</summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>Gets or sets the standard-base64 encoded, 32-byte shared secret.</summary>
    public string SecretBase64 { get; set; } = string.Empty;

    /// <inheritdoc/>
    public override string ToString() => $"Audience = {Audience}, KeyId = {KeyId}";
}
