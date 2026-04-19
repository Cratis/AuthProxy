// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_tenant_is_not_found;

/// <summary>
/// WebApplicationFactory that configures tenant verification so the verifier returns "not found"
/// for the fixed test tenant, causing the TenancyMiddleware to serve the tenant-not-found error page.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string TenantVerificationBaseUrl = "http://tenant-verify.test/";
    public const string IdentityBackendBaseUrl = "http://identity.test/";
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>Initializes a new instance of the <see cref="AuthProxyFactory"/> class.</summary>
    public AuthProxyFactory()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "tenant-not-found.html"), "<html><body><h1>Tenant Not Found</h1></body></html>");
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
        builder
            .UseEnvironment("Test")
            .ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Tenant resolution: always resolve to fixed tenant ID
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

                // Tenant verification: the verifier will call this URL and receive 404 (not found)
                [$"{C.AuthProxy.SectionKey}:TenantVerification:UrlTemplate"] = $"{TenantVerificationBaseUrl}tenants/{{tenantId}}",

                [$"{C.AuthProxy.SectionKey}:Services:test:Backend:BaseUrl"] = IdentityBackendBaseUrl,
                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(TestAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, _ => { });

            // The factory returns 404 for the tenant verification URL, which makes TenantVerifier
            // report the tenant as not found. All other URLs also return 404.
            services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(
                _ => new HttpResponseMessage(HttpStatusCode.NotFound)));
        });
    }

    /// <summary>Creates a test HTTP client that does not follow redirects.</summary>
    /// <param name="authenticated">Whether the client should appear authenticated.</param>
    /// <returns>A configured <see cref="HttpClient"/> that does not follow redirects.</returns>
    public HttpClient CreateTestClient(bool authenticated = false)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (authenticated)
            client.DefaultRequestHeaders.Add(TestAuthHandler.AuthHeader, "true");
        return client;
    }

    /// <summary>Authentication handler that authenticates a request when the X-Test-Auth header is present.</summary>
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
        public const string AuthHeader = "X-Test-Auth";

        /// <inheritdoc/>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(AuthHeader))
                return Task.FromResult(AuthenticateResult.NoResult());

            var claims = new[] { new Claim(ClaimTypes.Name, "test-user"), new Claim("sub", "test-user-id") };
            var identity = new ClaimsIdentity(claims, Scheme);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme)));
        }
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
