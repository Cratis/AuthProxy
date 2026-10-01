// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the Azure Key Vault key newly generated Data Protection keys are encrypted with before they are stored.
/// </summary>
/// <remarks>
/// Applies to every <see cref="DataProtectionStore"/>. The identity AuthProxy runs as needs to wrap and unwrap
/// with the key — for example the <c language="text">Key Vault Crypto User</c> role. Existing plaintext keys remain
/// readable and are not retroactively encrypted. Existing encrypted keys still require their original vault
/// keys and versions, even after this identifier changes. Keep those keys available and this protection
/// configured while using the existing ring. To start a new ring and invalidate sessions and tokens,
/// deliberately configure a fresh key repository on every replica.
/// </remarks>
public class KeyVaultKeyProtection
{
    /// <summary>
    /// Gets or sets the absolute <c language="text">https</c> identifier of the key, for example
    /// <c language="text">https://myvault.vault.azure.net/keys/authproxy-dataprotection</c>. A version may be appended.
    /// </summary>
    public string KeyIdentifier { get; set; } = string.Empty;
}
