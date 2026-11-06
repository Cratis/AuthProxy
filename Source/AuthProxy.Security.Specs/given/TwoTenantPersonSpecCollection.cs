// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the two-tenant browser deployment.</summary>
[CollectionDefinition(Name)]
public class TwoTenantPersonSpecCollection : ICollectionFixture<TwoTenantPersonHarness>
{
    /// <summary>The collection name.</summary>
    public const string Name = "TwoTenantPerson";
}
