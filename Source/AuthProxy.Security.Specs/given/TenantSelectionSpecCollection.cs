// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Shares one <see cref="TenantSelectionHarness"/> across the tenant selection specs.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class TenantSelectionSpecCollection : ICollectionFixture<TenantSelectionHarness>
{
    /// <summary>The collection name every tenant selection spec joins.</summary>
    public const string Name = "TenantSelection";
}
