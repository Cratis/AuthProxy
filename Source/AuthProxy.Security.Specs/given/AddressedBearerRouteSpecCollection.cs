// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the addressed bearer deployment.</summary>
[CollectionDefinition(Name)]
public class AddressedBearerRouteSpecCollection : ICollectionFixture<AddressedBearerRouteHarness>
{
    /// <summary>The collection name.</summary>
    public const string Name = "AddressedBearerRoutes";
}
