// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Shares one <see cref="UpstreamRequestsHarness"/> across the upstream request specs.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class UpstreamRequestsSpecCollection : ICollectionFixture<UpstreamRequestsHarness>
{
    /// <summary>The collection name every upstream request spec joins.</summary>
    public const string Name = "UpstreamRequests";
}
