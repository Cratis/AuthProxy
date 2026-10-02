// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Shares one <see cref="AccessTokenForwardingHarness"/> across the access-token forwarding specs.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class AccessTokenForwardingSpecCollection : ICollectionFixture<AccessTokenForwardingHarness>
{
    /// <summary>The collection name every access-token forwarding spec joins.</summary>
    public const string Name = "AccessTokenForwarding";
}
