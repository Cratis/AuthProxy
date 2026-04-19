// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_multiple_providers_are_configured;

/// <summary>
/// WebApplicationFactory that configures two OIDC providers and a select-provider page
/// to verify that unauthenticated general requests are intercepted by SelectProviderMiddleware.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>Initializes a new instance of the <see cref="AuthProxyFactory"/> class.</summary>
    public AuthProxyFactory()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "select-provider.html"), "<html><body><h1>Select Provider</h1></body></html>");
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_pagesPath))
            Directory.Delete(_pagesPath, recursive: true);
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,
                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.com/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Name"] = "Provider Two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Authority"] = "https://login.example.com/two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:ClientId"] = "client-two",
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(TestAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, _ => { });

            services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(
                _ => new HttpResponseMessage(HttpStatusCode.NotFound)));
        });
    }

    /// <summary>Creates a test HTTP client that does not follow redirects.</summary>
    /// <returns>A configured <see cref="HttpClient"/> that does not follow redirects.</returns>
    public HttpClient CreateTestClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    /// <summary>Authentication handler that never authenticates (unauthenticated requests).</summary>
    /// <param name="options">The options monitor for authentication scheme options.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    public class TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string Scheme = "TestScheme";

        /// <inheritdoc/>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());
    }

    /// <summary>Minimal IHttpClientFactory that routes all calls through a single handler.</summary>
    /// <param name="handler">The request dispatch function.</param>
    sealed class TestHttpClientFactory(Func<string, HttpResponseMessage> handler) : IHttpClientFactory
    {
        /// <inheritdoc/>
        public HttpClient CreateClient(string name) =>
            new(new DispatchingHandler(handler)) { Timeout = TimeSpan.FromSeconds(10) };

        sealed class DispatchingHandler(Func<string, HttpResponseMessage> handler) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                Task.FromResult(handler(request.RequestUri?.ToString() ?? string.Empty));
        }
    }
}
