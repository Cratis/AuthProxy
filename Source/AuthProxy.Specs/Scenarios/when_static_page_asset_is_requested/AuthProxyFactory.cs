// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_static_page_asset_is_requested;

public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string IdentityBackendBaseUrl = "http://identity.test/";
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public AuthProxyFactory()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "403.html"), "<html><head><link rel=\"stylesheet\" href=\"styles.css\" /></head><body><img src=\"logo.svg\" /></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "styles.css"), "body { color: red; }");
        File.WriteAllText(Path.Combine(_pagesPath, "logo.svg"), "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_pagesPath))
        {
            Directory.Delete(_pagesPath, recursive: true);
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:test:Backend:BaseUrl"] = IdentityBackendBaseUrl,
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,
                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(TestAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, _ => { });

            services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(
                _ => new HttpResponseMessage(HttpStatusCode.Forbidden)));
        });
    }

    public HttpClient CreateTestClient(bool authenticated = false)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (authenticated)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.AuthHeader, "true");
        }

        return client;
    }

    public class TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string Scheme = "TestScheme";
        public const string AuthHeader = "X-Test-Auth";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(AuthHeader))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var claims =
                new[]
                {
                    new Claim(ClaimTypes.Name, "test-user"),
                    new Claim("sub", "test-user-id"),
                    new Claim("oid", "test-user-id"),
                };
            var identity = new ClaimsIdentity(claims, Scheme);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme)));
        }
    }

    sealed class TestHttpClientFactory(Func<string, HttpResponseMessage> handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new DispatchingHandler(handler)) { Timeout = TimeSpan.FromSeconds(10) };

        sealed class DispatchingHandler(Func<string, HttpResponseMessage> handler) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                Task.FromResult(handler(request.RequestUri?.ToString() ?? string.Empty));
        }
    }
}