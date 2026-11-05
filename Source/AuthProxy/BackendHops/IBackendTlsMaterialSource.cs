// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Supplies the latest valid mounted TLS material.
/// </summary>
internal interface IBackendTlsMaterialSource
{
    /// <summary>
    /// Gets the current coherent snapshot.
    /// </summary>
    BackendTlsMaterial Current { get; }

    /// <summary>
    /// Re-reads mounted files, retaining the last valid snapshot on failure.
    /// </summary>
    /// <returns>Whether different valid material replaced the snapshot.</returns>
    bool TryReload();
}
