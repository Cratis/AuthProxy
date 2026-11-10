// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>Configures the authoritative shared replay store.</summary>
public sealed class DpopReplay
{
    /// <summary>Gets or sets the Redis configuration, independently of Data Protection storage.</summary>
    public DpopRedis Redis { get; set; } = new();
}
