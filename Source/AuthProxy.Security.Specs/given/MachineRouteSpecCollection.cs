// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Shares the machine route deployment.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class MachineRouteSpecCollection : ICollectionFixture<MachineRouteHarness>
{
    /// <summary>The collection name.</summary>
    public const string Name = "Machine route headers";
}
