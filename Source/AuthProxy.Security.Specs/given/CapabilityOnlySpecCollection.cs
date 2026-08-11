// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the capability-only specs against one shared proxy and origin, in sequence.
/// </summary>
/// <remarks>
/// Its own collection because it is its own deployment, with its own origin recording its own traffic.
/// Serialized for the same reason the others are: two specs reading one recorder would read each other's
/// requests, and the whole assertion here is that the recorder stayed empty.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public class CapabilityOnlySpecCollection : ICollectionFixture<CapabilityOnlyHarness>
{
    /// <summary>The collection name every capability-only spec joins.</summary>
    public const string Name = "CapabilityOnly";
}
