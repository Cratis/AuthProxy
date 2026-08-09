// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the claim-gated specs against one shared proxy and origin, in sequence.
/// </summary>
/// <remarks>
/// Separate from <see cref="SecuritySpecCollection"/> because it is a different deployment, with its own
/// origin recording its own traffic. Serialized for the same reason that one is: two specs reading one
/// recorder would read each other's requests.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public class ClaimGateSpecCollection : ICollectionFixture<ClaimGatedHarness>
{
    /// <summary>The collection name every claim-gated spec joins.</summary>
    public const string Name = "ClaimGate";
}
