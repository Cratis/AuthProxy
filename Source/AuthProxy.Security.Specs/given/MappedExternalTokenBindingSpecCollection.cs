// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the mapped JWT deployment.</summary>
[CollectionDefinition(Name)]
public class MappedExternalTokenBindingSpecCollection : ICollectionFixture<MappedExternalTokenBindingHarness>
{
    /// <summary>The collection name.</summary>
    public const string Name = "MappedExternalTokenBinding";
}
