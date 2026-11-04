// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A sticky proxy whose discovery can lose one replica while both origins remain alive.
/// </summary>
public class ReplicaRemovalHarness : StickyRoutingHarness
{
    readonly MutableReplicaDiscovery _discovery;

    /// <summary>
    /// Initializes a new instance of the <see cref="ReplicaRemovalHarness"/> class.
    /// </summary>
    public ReplicaRemovalHarness() => _discovery = new(new Uri(Backend.BaseUrl), new Uri(Replica.BaseUrl));

    /// <summary>
    /// Removes only the specified origin from subsequent discovery answers.
    /// </summary>
    /// <param name="origin">The replica that leaves discovery.</param>
    public void Remove(RecordingBackend origin) => _discovery.Remove(new Uri(origin.BaseUrl));

    /// <summary>
    /// Creates an authenticated request carrying an explicit affinity cookie, if supplied.
    /// </summary>
    /// <param name="path">The backend path.</param>
    /// <param name="cookie">The affinity cookie to replay.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage SignedIn(string path, string cookie = "")
    {
        var request = FromSession(path, "session-one");
        if (cookie.Length > 0)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }
        return request;
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:reporting:Backend:StickyRouting:RefreshInterval"] = "00:00:01",
        }));
        builder.ConfigureTestServices(services => services.AddSingleton<IReplicaDiscovery>(_discovery));
    }

    sealed class MutableReplicaDiscovery(Uri backend, Uri replica) : IReplicaDiscovery
    {
        volatile IReadOnlyList<Uri> _replicas = [backend, replica];

        public void Remove(Uri origin) => _replicas = _replicas.Where(replica => replica != origin).ToArray();

        public Task<IReadOnlyList<Uri>> Discover(Uri baseUrl, string replicaHost, CancellationToken cancellationToken) =>
            Task.FromResult(_replicas);
    }
}
