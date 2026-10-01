// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the Azure Blob Storage blob the Data Protection key ring is persisted to.
/// </summary>
/// <remarks>
/// The blob is reached with the credential described on <see cref="DataProtection"/>, so the identity AuthProxy
/// runs as needs read and write access to it — for example the <c language="text">Storage Blob Data Contributor</c> role on the
/// container. The container has to exist; the blob is created on first use.
/// </remarks>
public class AzureBlobKeyStore
{
    /// <summary>
    /// Gets or sets the absolute <c language="text">https</c> URI of the blob, for example
    /// <c language="text">https://myaccount.blob.core.windows.net/dataprotection/keys.xml</c>.
    /// </summary>
    public string BlobUri { get; set; } = string.Empty;
}
