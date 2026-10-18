// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the signed forwarding specs against one shared signing proxy and its origins, in sequence, so no spec reads
/// another's traffic from the recording origins.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class SignedForwardingSpecCollection : ICollectionFixture<SignedForwardingHarness>
{
    /// <summary>The collection name every signed forwarding spec joins.</summary>
    public const string Name = "SignedForwarding";
}
