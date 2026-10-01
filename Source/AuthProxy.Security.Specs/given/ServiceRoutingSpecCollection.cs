// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Shares one <see cref="ServiceRoutingHarness"/> across the host and path-prefix routing specs.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class ServiceRoutingSpecCollection : ICollectionFixture<ServiceRoutingHarness>
{
    /// <summary>The collection name every service-routing spec joins.</summary>
    public const string Name = "ServiceRouting";
}
