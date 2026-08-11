// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the closed-deployment listener specs against one pair of running proxies, in sequence.
/// </summary>
/// <remarks>
/// Its own collection because it binds real ports and shares one recording origin with itself, and
/// serialized for the same reason the others are: the assertion is that the origin saw nothing, which a
/// second spec's traffic would falsify.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public class ClosedDeploymentSpecCollection : ICollectionFixture<ClosedDeploymentHarness>
{
    /// <summary>The collection name every closed-deployment listener spec joins.</summary>
    public const string Name = "ClosedDeployment";
}
