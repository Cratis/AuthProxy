// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs every bearer-route spec against one shared proxy, origin and issuer, in sequence, so no spec reads
/// another's traffic from the recording origin.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class BearerRouteSpecCollection : ICollectionFixture<BearerRouteHarness>
{
    /// <summary>The collection name every bearer-route spec joins.</summary>
    public const string Name = "BearerRoutes";
}
