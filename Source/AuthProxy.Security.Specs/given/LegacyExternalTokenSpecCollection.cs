// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the unbound JWT deployment.</summary>
[CollectionDefinition(Name)]
public class LegacyExternalTokenSpecCollection : ICollectionFixture<LegacyExternalTokenHarness>
{
    /// <summary>The collection name.</summary>
    public const string Name = "LegacyExternalToken";
}
