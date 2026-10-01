// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the Azure Key Vault key the Data Protection key ring is encrypted with before it is stored.
/// </summary>
/// <remarks>
/// Applies to every <see cref="DataProtectionStore"/>, so a key ring on a shared volume or in Redis is not
/// readable by whoever can read the store. The identity AuthProxy runs as needs to wrap and unwrap with the
/// key — for example the <c language="text">Key Vault Crypto User</c> role. A key ring written without this setting is not
/// readable once it is turned on, and the reverse: changing it starts a new key ring and signs everyone out.
/// </remarks>
public class KeyVaultKeyProtection
{
    /// <summary>
    /// Gets or sets the absolute <c language="text">https</c> identifier of the key, for example
    /// <c language="text">https://myvault.vault.azure.net/keys/authproxy-dataprotection</c>. A version may be appended.
    /// </summary>
    public string KeyIdentifier { get; set; } = string.Empty;
}
