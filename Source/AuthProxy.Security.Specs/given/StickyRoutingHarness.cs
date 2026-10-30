// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A proxy with sticky routing to two local Kestrel origins, substituting discovery but not YARP's routing.
/// </summary>
public class StickyRoutingHarness : AccessTokenForwardingHarness
{
    /// <summary>Initializes a new instance of the <see cref="StickyRoutingHarness"/> class.</summary>
    public StickyRoutingHarness() => Replica = RecordingBackend.Start().GetAwaiter().GetResult();

    /// <summary>Gets the second backend replica.</summary>
    public RecordingBackend Replica { get; }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:reporting:Backend:StickyRouting:Enabled"] = "true",
            [$"{C.AuthProxy.SectionKey}:Services:reporting:Backend:StickyRouting:ReplicaHost"] = "reporting-replicas.example.test",
        }));
        builder.ConfigureTestServices(services => services.AddSingleton<IReplicaDiscovery>(new StandInReplicaDiscovery(Backend.BaseUrl, Replica.BaseUrl)));
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            Replica.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    sealed class StandInReplicaDiscovery(string backend, string replica) : IReplicaDiscovery
    {
        public Task<IReadOnlyList<Uri>> Discover(Uri baseUrl, string replicaHost, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<Uri>>([new Uri(backend), new Uri(replica)]);
    }
}
