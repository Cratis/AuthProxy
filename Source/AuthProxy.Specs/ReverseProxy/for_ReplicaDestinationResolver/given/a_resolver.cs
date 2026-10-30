// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Logging.Abstractions;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.ServiceDiscovery;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver.given;

/// <summary>
/// A resolver over a substituted discovery, and a sticky seed destination to resolve.
/// </summary>
public class a_resolver : Specification
{
    protected const string SeedId = "core-backend-destination-abc";
    protected const string SeedAddress = "https://core:8443/";

    protected IReplicaDiscovery _discovery;
    internal ReplicaDestinationResolver _resolver;
    protected ResolvedDestinationCollection _result;

    protected static Uri Replica(string address) => new($"https://{address}:8443/");

    protected static DestinationConfig Seed(string address = SeedAddress) => new()
    {
        Address = address,
        Metadata = new Dictionary<string, string>
        {
            [MicroserviceReverseProxyConfigProvider.ServiceMetadataKey] = "core",
            [MicroserviceReverseProxyConfigProvider.ReplicaHostMetadataKey] = "core-headless",
            [MicroserviceReverseProxyConfigProvider.ReplicaRefreshMetadataKey] = "00:00:15",
        },
    };

    protected static Dictionary<string, DestinationConfig> Seeded(string address = SeedAddress) => new() { [SeedId] = Seed(address) };

    protected void Discovers(params string[] addresses) =>
        _discovery.Discover(Arg.Any<Uri>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<Uri>>([.. addresses.Select(Replica)]));

    protected void Fails() =>
        _discovery.Discover(Arg.Any<Uri>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException<IReadOnlyList<Uri>>(new InvalidOperationException("dns")));

    protected ValueTask<ResolvedDestinationCollection> Resolve(Dictionary<string, DestinationConfig>? destinations = null, CancellationToken cancellationToken = default) =>
        _resolver.ResolveDestinationsAsync(destinations ?? Seeded(), cancellationToken);

    void Establish()
    {
        _discovery = Substitute.For<IReplicaDiscovery>();
        _resolver = new(_discovery, TimeProvider.System, NullLogger<ReplicaDestinationResolver>.Instance);
    }

    void Destroy() => _resolver.Dispose();
}
