// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the Redis key the Data Protection key ring is persisted to.
/// </summary>
public class RedisKeyStore
{
    /// <summary>
    /// The Redis key used when <see cref="Key"/> is not set.
    /// </summary>
    public const string DefaultKey = "Cratis.AuthProxy:DataProtection-Keys";

    /// <summary>
    /// Gets or sets the StackExchange.Redis connection string, for example
    /// <c language="text">my-cache.redis.cache.windows.net:6380,password=...,ssl=true</c>.
    /// </summary>
    /// <remarks>
    /// It usually carries a credential, so supply it from a secret store or an environment variable rather
    /// than a file checked into source control.
    /// </remarks>
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Redis key holding the key ring. Defaults to <see cref="DefaultKey"/>. Give
    /// deployments sharing one Redis their own value, or they share a key ring.
    /// </summary>
    public string Key { get; set; } = DefaultKey;
}
