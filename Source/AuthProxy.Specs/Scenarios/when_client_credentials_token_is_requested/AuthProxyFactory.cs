// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Http.Json;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

/// <summary>
/// Web application factory for exercising the back-channel client-credentials token endpoint.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    public ClientCredentialsVerificationRequest? CapturedVerificationRequest { get; private set; }

    protected virtual HttpStatusCode VerificationStatusCode => HttpStatusCode.NoContent;

    protected virtual object? VerificationResponseBody => null;

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

                [$"{C.AuthProxy.SectionKey}:Services:portal:Backend:BaseUrl"] = "http://portal.test/",
                [$"{C.AuthProxy.SectionKey}:Services:portal:ClientCredentials:RoutePrefix"] = "/api",
                [$"{C.AuthProxy.SectionKey}:Services:portal:ClientCredentials:VerificationPath"] = "/.cratis/client-credentials/verify",

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Microsoft",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.com/common/v2.0",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "browser-client",
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(async request =>
            {
                if (request.Content is not null)
                {
                    CapturedVerificationRequest = await request.Content.ReadFromJsonAsync<ClientCredentialsVerificationRequest>();
                }

                var response = new HttpResponseMessage(VerificationStatusCode);
                if (VerificationResponseBody is not null)
                {
                    response.Content = JsonContent.Create(VerificationResponseBody);
                }

                return response;
            }));
        });
    }

    /// <summary>
    /// Creates a test HTTP client that does not follow redirects.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateTestClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    sealed class TestHttpClientFactory(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new DispatchingHandler(handler)) { Timeout = TimeSpan.FromSeconds(10) };

        sealed class DispatchingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                handler(request);
        }
    }
}
