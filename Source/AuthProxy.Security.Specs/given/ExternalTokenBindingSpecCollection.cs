// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the general JWT deployment and its recording origin.</summary>
[CollectionDefinition(Name)]
public class ExternalTokenBindingSpecCollection : ICollectionFixture<ExternalTokenBindingHarness>
{
    /// <summary>The collection name.</summary>
    public const string Name = "ExternalTokenBinding";
}
