// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the pair of environment-bound proxies.</summary>
[CollectionDefinition(Name)]
public class EnvironmentBindingSpecCollection : ICollectionFixture<EnvironmentBindingHarness>
{
    /// <summary>The collection name.</summary>
    public const string Name = "EnvironmentBinding";
}
