// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Cratis.AuthProxy.Management.for_DataProtectionReadiness.given;

/// <summary>
/// Key storage that cannot be read or written — what a mounted keys volume that is missing, unwritable, or
/// no longer attached looks like from inside Data Protection.
/// </summary>
public sealed class UnreachableKeyStorage : IXmlRepository
{
    /// <inheritdoc/>
    public IReadOnlyCollection<XElement> GetAllElements() => throw new IOException("The key ring directory is unreachable.");

    /// <inheritdoc/>
    public void StoreElement(XElement element, string friendlyName) => throw new IOException("The key ring directory is unreachable.");
}
