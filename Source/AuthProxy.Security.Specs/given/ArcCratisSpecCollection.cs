// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the real proxy and serializes observations at the Arc origin.</summary>
[CollectionDefinition(Name)]
public class ArcCratisSpecCollection : ICollectionFixture<ArcCratisHarness>
{
    public const string Name = "Arc Cratis paths";
}
