// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the sticky proxy and local origins without parallel requests from other scenarios.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class StickyRoutingSpecCollection : ICollectionFixture<StickyRoutingHarness>
{
    /// <summary>The sticky routing collection name.</summary>
    public const string Name = "StickyRouting";
}
