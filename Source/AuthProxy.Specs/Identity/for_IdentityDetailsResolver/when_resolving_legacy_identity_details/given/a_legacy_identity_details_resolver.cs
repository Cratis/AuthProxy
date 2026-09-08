// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_resolving_legacy_identity_details.given;

/// <summary>
/// Provides an identity details resolver backed by a controllable identity endpoint, for principals that
/// carry no canonical reserved claims and therefore resolve through the legacy binding.
/// </summary>
public class a_legacy_identity_details_resolver : Specification
{
    protected const string TenantId = "tenant-a";

    protected CountingIdentityHandler _handler;
    protected C.AuthProxy _configuration;
    protected IdentityDetailsResolver _resolver;

    void Establish()
    {
        _handler = new CountingIdentityHandler();
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler, disposeHandler: false));
        _configuration = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" } }
            }
        };
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(_ => _configuration);
        _resolver = new IdentityDetailsResolver(
            options,
            clients,
            [],
            new MemoryCache(new MemoryCacheOptions()),
            Substitute.For<IIdentityAuthorizationCache>(),
            Substitute.For<ILogger<IdentityDetailsResolver>>());
    }

    /// <summary>
    /// Builds a legacy principal carrying no reserved claims.
    /// </summary>
    /// <param name="userId">The raw provider-supplied user identifier.</param>
    /// <returns>The principal.</returns>
    protected static ClientPrincipal LegacyPrincipal(string userId) => new() { UserId = userId };

    /// <summary>
    /// Counts identity endpoint calls and returns a distinct successful response for each call.
    /// </summary>
    protected sealed class CountingIdentityHandler : HttpMessageHandler
    {
        int _calls;

        /// <summary>
        /// Gets the number of requests received by the handler.
        /// </summary>
        public int Calls => _calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _calls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{{\"details\":{{\"call\":{call}}}}}")
            });
        }
    }
}
