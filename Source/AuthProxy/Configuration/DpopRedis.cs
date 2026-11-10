// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>Configures atomic Redis replay reservations shared by every replica.</summary>
public sealed class DpopRedis
{
    /// <summary>Gets or sets the Redis connection. Supply it through the deployment's secret mechanism.</summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>Gets or sets the deployment-specific replay namespace. Never share a prefix between deployments.</summary>
    public string KeyPrefix { get; set; } = "Cratis.AuthProxy:Dpop";
}
