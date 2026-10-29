// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Serializes forwarding-path scenarios against their own proxy and recording origins.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class ForwardingPathSpecCollection : ICollectionFixture<ForwardingPathHarness>
{
    /// <summary>The collection name for service forwarding-path specs.</summary>
    public const string Name = "ForwardingPaths";
}
