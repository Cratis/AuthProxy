// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

internal static partial class ReplicaDestinationResolverLogging
{
    [LoggerMessage(LogLevel.Debug, "Service '{Service}' has {Count} backend replica(s).")]
    internal static partial void ReplicasDiscovered(this ILogger logger, string service, int count);

    [LoggerMessage(LogLevel.Warning, "No backend replicas were discovered for service '{Service}'; its configured BaseUrl is used.")]
    internal static partial void NoReplicasDiscovered(this ILogger logger, string service);

    [LoggerMessage(LogLevel.Warning, "Discovering backend replicas for service '{Service}' through '{ReplicaHost}' failed; the last known replicas or the configured BaseUrl are used.")]
    internal static partial void ReplicaDiscoveryFailed(this ILogger logger, string service, string replicaHost, Exception exception);
}
