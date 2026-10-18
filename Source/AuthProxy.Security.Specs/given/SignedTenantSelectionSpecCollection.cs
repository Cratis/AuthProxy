// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the signed tenant-selection specs against one shared proxy and origin, in sequence.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class SignedTenantSelectionSpecCollection : ICollectionFixture<SignedTenantSelectionHarness>
{
    /// <summary>The collection name every signed tenant-selection spec joins.</summary>
    public const string Name = "SignedTenantSelection";
}
