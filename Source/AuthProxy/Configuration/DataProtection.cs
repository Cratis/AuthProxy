// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents where AuthProxy keeps its ASP.NET Core Data Protection key ring, and how that ring is protected.
/// </summary>
/// <remarks>
/// The key ring encrypts the authentication cookie and every token AuthProxy issues, so replicas that do not
/// share one cannot read each other's sessions, and a replica that restarts without one signs everybody out.
/// <para>
/// Leaving this section out keeps the released behavior: the key ring is persisted to
/// <see cref="AuthProxy.DataProtectionKeysPath"/> when that is set, and is the framework's per-machine default
/// when it is not.
/// </para>
/// <para>
/// The Azure stores authenticate with <c language="text">DefaultAzureCredential</c>: a managed identity or workload identity
/// in Azure, the developer's sign-in locally. No secret is configured here.
/// </para>
/// </remarks>
public class DataProtection
{
    /// <summary>
    /// The configuration section key for the Data Protection settings.
    /// </summary>
    public const string SectionKey = $"{AuthProxy.SectionKey}:DataProtection";

    /// <summary>
    /// Gets or sets where the key ring is persisted. Defaults to <see cref="DataProtectionStore.FileSystem"/>.
    /// </summary>
    public DataProtectionStore Store { get; set; } = DataProtectionStore.FileSystem;

    /// <summary>
    /// Gets or sets the blob the key ring is persisted to. Required, and only allowed, when
    /// <see cref="Store"/> is <see cref="DataProtectionStore.AzureBlob"/>.
    /// </summary>
    public AzureBlobKeyStore? AzureBlob { get; set; }

    /// <summary>
    /// Gets or sets the Redis key the key ring is persisted to. Required, and only allowed, when
    /// <see cref="Store"/> is <see cref="DataProtectionStore.Redis"/>.
    /// </summary>
    public RedisKeyStore? Redis { get; set; }

    /// <summary>
    /// Gets or sets the Azure Key Vault key that encrypts the key ring at rest. Optional, and usable with any
    /// <see cref="Store"/>.
    /// </summary>
    public KeyVaultKeyProtection? KeyVault { get; set; }

    /// <summary>
    /// Gets or sets the client ID of the user-assigned managed identity to authenticate to Azure with. Leave
    /// unset to use the system-assigned identity, or whatever <c language="text">DefaultAzureCredential</c> finds first.
    /// </summary>
    public string? ManagedIdentityClientId { get; set; }
}
