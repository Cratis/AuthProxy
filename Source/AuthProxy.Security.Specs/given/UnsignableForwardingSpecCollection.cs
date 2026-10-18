// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the specs for a proxy that cannot sign against one shared proxy and origin, in sequence.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class UnsignableForwardingSpecCollection : ICollectionFixture<UnsignableForwardingHarness>
{
    /// <summary>The collection name every unsignable forwarding spec joins.</summary>
    public const string Name = "UnsignableForwarding";
}
