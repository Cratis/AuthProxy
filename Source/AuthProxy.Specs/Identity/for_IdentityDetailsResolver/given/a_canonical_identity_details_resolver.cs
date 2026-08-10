// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

/// <summary>
/// Provides an identity details resolver backed by a controllable identity endpoint.
/// </summary>
public class a_canonical_identity_details_resolver : Specification
{
    protected const string TenantId = "tenant-a";
    protected const string Subject = "shared-subject";

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

    protected static ClientPrincipal Principal(string providerKey, string issuer) =>
        new()
        {
            IdentityProvider = providerKey,
            UserId = Subject,
            Claims =
            [
                new() { Type = CanonicalIdentityClaims.ProviderKey, Value = providerKey },
                new() { Type = CanonicalIdentityClaims.Issuer, Value = issuer },
                new() { Type = CanonicalIdentityClaims.Subject, Value = Subject }
            ]
        };

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
