// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// WebApplicationFactory that configures two OIDC providers — so an unauthenticated request would
/// otherwise be answered with the provider-selection page — alongside a service that declares two
/// anonymous path prefixes.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    /// <summary>The declared anonymous SPA prefix, served by the frontend endpoint.</summary>
    public const string AnonymousFrontendPath = "/portal";

    /// <summary>The declared anonymous API leaf path, served by the backend endpoint.</summary>
    public const string AnonymousBackendPath = "/api/portal/report";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>Initializes a new instance of the <see cref="AuthProxyFactory"/> class.</summary>
    public AuthProxyFactory()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "select-provider.html"), "<html><body><h1>Select Provider</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "select-tenant.html"), "<html><body><h1>Select Tenant</h1></body></html>");
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_pagesPath))
            Directory.Delete(_pagesPath, recursive: true);
    }

    /// <summary>
    /// Gets the tenant-resolution settings the host runs with.
    /// Defaults to a strategy that always resolves, so that <c>TenancyMiddleware</c> never reaches its
    /// tenant-unresolved branch and the scenario measures the other enforcement points on their own.
    /// </summary>
    protected virtual IEnumerable<KeyValuePair<string, string?>> TenantResolutionSettings =>
    [
        new($"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy", nameof(C.TenantSourceIdentifierResolverType.Specified)),
        new($"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId", TenantId),
    ];

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:test:Backend:BaseUrl"] = "http://backend.test/",
                [$"{C.AuthProxy.SectionKey}:Services:test:Frontend:BaseUrl"] = "http://frontend.test/",
                [$"{C.AuthProxy.SectionKey}:Services:test:AnonymousPaths:0"] = AnonymousFrontendPath,
                [$"{C.AuthProxy.SectionKey}:Services:test:AnonymousPaths:1"] = AnonymousBackendPath,

                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.com/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Name"] = "Provider Two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Authority"] = "https://login.example.com/two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:ClientId"] = "client-two",
            });

            config.AddInMemoryCollection(TenantResolutionSettings);
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

    /// <summary>
    /// Creates a request shaped like a browser navigating to a page, which is the only caller an HTML
    /// selection page is served to.
    /// </summary>
    /// <param name="path">The path to request.</param>
    /// <returns>A request carrying the fetch metadata a document navigation sends.</returns>
    public static HttpRequestMessage BrowserNavigation(string path) =>
        new(HttpMethod.Get, path) { Headers = { { "Sec-Fetch-Dest", "document" } } };

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
