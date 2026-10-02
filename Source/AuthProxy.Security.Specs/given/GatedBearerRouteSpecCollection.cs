// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs every spec against the bearer-route deployment that declares claim requirements and identity verification,
/// in sequence.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class GatedBearerRouteSpecCollection : ICollectionFixture<GatedBearerRouteHarness>
{
    /// <summary>The collection name every spec against that deployment joins.</summary>
    public const string Name = "GatedBearerRoutes";
}
