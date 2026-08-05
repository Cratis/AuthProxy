// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs every security spec against one shared proxy and origin, in sequence.
/// </summary>
/// <remarks>
/// The origin records what it received, and a spec reads that record to decide whether an attack got
/// through. Two specs running concurrently against one recorder would read each other's traffic, so the
/// collection serializes them. It also means the proxy host and the origin are started once rather than
/// per spec class, which is what keeps a suite this size fast enough to sit on every pull request.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public class SecuritySpecCollection : ICollectionFixture<SecurityHarness>
{
    /// <summary>The collection name every security spec joins.</summary>
    public const string Name = "Security";
}
