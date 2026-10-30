// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Primitives;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.ServiceDiscovery;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Replaces the configured destination of a sticky service with one destination per discovered replica.
/// </summary>
/// <remarks>
/// Destinations that do not ask for replicas pass through untouched. The resolver never throws because of
/// discovery: YARP turns a throwing resolver into a failed configuration load. A failure keeps the last known
/// replicas while the seed is unchanged, and otherwise falls back to the configured address.
/// </remarks>
/// <param name="discovery">The <see cref="IReplicaDiscovery"/> that finds the replicas.</param>
/// <param name="timeProvider">The <see cref="TimeProvider"/> that schedules the refresh.</param>
/// <param name="logger">The <see cref="ILogger"/> for diagnostics.</param>
sealed class ReplicaDestinationResolver(
    IReplicaDiscovery discovery,
    TimeProvider timeProvider,
    ILogger<ReplicaDestinationResolver> logger) : IDestinationResolver, IDisposable
{
    static readonly TimeSpan _failureRetryCap = TimeSpan.FromSeconds(5);

    readonly ConcurrentDictionary<string, KnownReplicas> _known = new();
    readonly ConcurrentDictionary<string, CancellationTokenSource> _refreshes = new();

    /// <summary>
    /// Gets how long a single discovery may take before it counts as failed.
    /// </summary>
    internal TimeSpan DiscoveryTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <inheritdoc/>
    public async ValueTask<ResolvedDestinationCollection> ResolveDestinationsAsync(
        IReadOnlyDictionary<string, DestinationConfig> destinations,
        CancellationToken cancellationToken)
    {
        if (!destinations.Values.Any(IsSeed))
        {
            return new ResolvedDestinationCollection(destinations, null);
        }

        var resolved = new Dictionary<string, DestinationConfig>();
        var tokens = new List<IChangeToken>();
        foreach (var (id, destination) in destinations)
        {
            if (!IsSeed(destination))
            {
                resolved[id] = destination;
                continue;
            }

            var (replicas, refreshAfter) = await Resolve(id, destination, cancellationToken);
            foreach (var (replicaId, replica) in replicas)
            {
                resolved[replicaId] = replica;
            }

            tokens.Add(RefreshToken(destination.Metadata![MicroserviceReverseProxyConfigProvider.ServiceMetadataKey], refreshAfter));
        }

        return new ResolvedDestinationCollection(
            resolved,
            tokens.Count == 1 ? tokens[0] : new CompositeChangeToken(tokens));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        // Disposed, not cancelled: shutting down must not trigger a re-resolution.
        foreach (var refresh in _refreshes.Values)
        {
            refresh.Dispose();
        }

        _refreshes.Clear();
    }

    static bool IsSeed(DestinationConfig destination) =>
        destination.Metadata?.ContainsKey(MicroserviceReverseProxyConfigProvider.ReplicaHostMetadataKey) == true;

    async Task<(IReadOnlyDictionary<string, DestinationConfig> Replicas, TimeSpan RefreshAfter)> Resolve(
        string seedId,
        DestinationConfig seed,
        CancellationToken cancellationToken)
    {
        var metadata = seed.Metadata!;
        var service = metadata[MicroserviceReverseProxyConfigProvider.ServiceMetadataKey];
        var replicaHost = metadata[MicroserviceReverseProxyConfigProvider.ReplicaHostMetadataKey];
        var interval = TimeSpan.ParseExact(
            metadata[MicroserviceReverseProxyConfigProvider.ReplicaRefreshMetadataKey],
            "c",
            CultureInfo.InvariantCulture);
        var retry = interval < _failureRetryCap ? interval : _failureRetryCap;
        var seedOnly = new Dictionary<string, DestinationConfig> { [seedId] = seed };
        var seedUri = new Uri(seed.Address);
        var identity = new KnownReplicas(seedId, replicaHost, seed.Address, null);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(DiscoveryTimeout);

            var found = await discovery.Discover(seedUri, replicaHost, timeout.Token);
            var replicas = found
                .Where(replica => replica.IsAbsoluteUri
                    && string.Equals(replica.Scheme, seedUri.Scheme, StringComparison.OrdinalIgnoreCase))
                .DistinctBy(replica => replica.Authority)
                .ToDictionary(
                    replica => ReplicaDestinations.IdFor(seedId, replica),
                    replica => seed with { Address = replica.ToString(), Host = seedUri.Authority });

            if (replicas.Count == 0)
            {
                logger.NoReplicasDiscovered(service);
                return (seedOnly, retry);
            }

            _known[service] = identity with { Replicas = replicas };
            logger.ReplicasDiscovered(service, replicas.Count);
            return (replicas, interval);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            logger.ReplicaDiscoveryFailed(service, replicaHost, ex);
            return _known.TryGetValue(service, out var known) && known.Replicas is not null && known with { Replicas = null } == identity
                ? (known.Replicas, retry)
                : (seedOnly, retry);
        }
    }

    CancellationChangeToken RefreshToken(string service, TimeSpan after)
    {
        var refresh = new CancellationTokenSource(after, timeProvider);
        _refreshes.TryGetValue(service, out var previous);
        _refreshes[service] = refresh;
        previous?.Dispose();

        return new CancellationChangeToken(refresh.Token);
    }

    sealed record KnownReplicas(string SeedId, string ReplicaHost, string SeedAddress, IReadOnlyDictionary<string, DestinationConfig>? Replicas);
}
