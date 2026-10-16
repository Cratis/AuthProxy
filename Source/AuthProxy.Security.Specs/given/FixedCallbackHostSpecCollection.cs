// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Shares one <see cref="FixedCallbackHostHarness"/> across the fixed callback host specs.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class FixedCallbackHostSpecCollection : ICollectionFixture<FixedCallbackHostHarness>
{
    /// <summary>The collection name every fixed callback host spec joins.</summary>
    public const string Name = "FixedCallbackHost";
}
