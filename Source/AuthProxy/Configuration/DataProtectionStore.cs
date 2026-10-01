// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Where AuthProxy persists its ASP.NET Core Data Protection key ring.
/// </summary>
public enum DataProtectionStore
{
    /// <summary>
    /// A directory on the file system, named by <see cref="AuthProxy.DataProtectionKeysPath"/>. Without that
    /// path the framework's default per-machine key ring is used, which is neither guaranteed to survive a
    /// restart nor shared between replicas. This is the default, and the released behavior.
    /// </summary>
    FileSystem = 0,

    /// <summary>
    /// A blob in Azure Blob Storage, named by <see cref="AzureBlobKeyStore.BlobUri"/>, shared by every
    /// replica.
    /// </summary>
    AzureBlob = 1,

    /// <summary>
    /// A key in Redis, named by <see cref="RedisKeyStore"/>, shared by every replica.
    /// </summary>
    Redis = 2,
}
