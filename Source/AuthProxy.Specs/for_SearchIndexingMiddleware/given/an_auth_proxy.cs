// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Management;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Forwarder;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware.given;

public class an_auth_proxy : Specification
{
    protected HttpClient _client;
    protected HttpResponseMessage _response;
    SearchIndexingAuthProxyFactory _factory;

    protected virtual bool Exclude => true;

    protected virtual IDictionary<string, string?> AdditionalSettings => new Dictionary<string, string?>();

    protected Task<HttpContext> ManagementRequest(string path) => _factory.Server.SendAsync(context =>
    {
        context.Connection.LocalPort = 9110;
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = path;
    });

    void Establish()
    {
        _factory = new(Exclude, AdditionalSettings);
        _client = _factory.CreateTestClient();
    }

    void Destroy()
    {
        _response?.Dispose();
        _client.Dispose();
        _factory.Dispose();
    }

    sealed class SearchIndexingAuthProxyFactory(bool exclude, IDictionary<string, string?> additionalSettings) : Scenarios.when_anonymous_paths_are_configured.AuthProxyFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder
                .ConfigureAppConfiguration((_, config) => config
                    .AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        [$"{C.AuthProxy.SectionKey}:SearchIndexing:Exclude"] = exclude.ToString()
                    })
                    .AddInMemoryCollection(additionalSettings))
                .ConfigureTestServices(services => services
                    .AddSingleton<IForwarderHttpClientFactory, ForwarderClients>()
                    .AddSingleton<IReadinessCheck, DataProtectionReadiness>());
        }
    }

    sealed class ForwarderClients : IForwarderHttpClientFactory
    {
        public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) => new(new Upstream());
    }

    sealed class Upstream : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("upstream response"),
                RequestMessage = request
            };
            if (request.RequestUri.AbsolutePath.EndsWith("/upstream-policy", StringComparison.Ordinal))
            {
                response.Headers.Add("X-Robots-Tag", "noarchive");
            }

            return Task.FromResult(response);
        }
    }
}
