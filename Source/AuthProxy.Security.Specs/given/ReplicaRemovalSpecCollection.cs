// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Serializes removal scenarios without sharing their mutable discovery or proxy state.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public static class ReplicaRemovalSpecCollection
{
    /// <summary>
    /// The replica removal collection name.
    /// </summary>
    public const string Name = "ReplicaRemoval";
}
