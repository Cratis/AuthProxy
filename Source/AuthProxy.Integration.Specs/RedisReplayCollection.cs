// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Integration.Specs;

/// <summary>Shares one Redis container across serialized replay scenarios.</summary>
[CollectionDefinition(Name)]
public class RedisReplayCollection : ICollectionFixture<RedisReplayFixture>
{
    /// <summary>The shared collection name.</summary>
    public const string Name = "Redis DPoP replay";
}
