// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares an isolated bearer forwarding-policy deployment without concurrent origin assertions.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class ForwardingPathBearerRouteSpecCollection : ICollectionFixture<ForwardingPathBearerRouteHarness>
{
    /// <summary>The collection name for bearer forwarding-path specs.</summary>
    public const string Name = "ForwardingPathBearerRoutes";
}
