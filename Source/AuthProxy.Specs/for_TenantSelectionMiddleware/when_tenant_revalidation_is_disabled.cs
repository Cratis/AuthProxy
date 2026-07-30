// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_tenant_revalidation_is_disabled : Specification
{
    TenantSelectionMiddleware _middleware;
    DefaultHttpContext _context;
    CountingTenantsHandler _handler;
    bool _nextCalled;

    void Establish()
    {
        var authProxyConfig = new C.AuthProxy
        {
            Session = new C.Session { TenantRevalidationInterval = TimeSpan.Zero },
            TenantResolutions =
            [
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.Selection,
                    Options = new SelectionOptions
                    {
                        TenantsEndpoint = "https://platform.example.com/api/tenants/selectable"
                    }
                }
            ]
        };
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(authProxyConfig);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<TenantResolutionResult>())
            .Returns(callInfo =>
            {
                callInfo[1] = new TenantResolutionResult("tenant-a", C.TenantSourceIdentifierResolverType.Selection);
                return true;
            });

        _handler = new CountingTenantsHandler();
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>())
            .Returns(_ => new HttpClient(_handler, disposeHandler: false));

        _middleware = new TenantSelectionMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config,
            tenantResolver,
            httpClientFactory,
            Substitute.For<IErrorPageProvider>(),
            new MemoryCache(new MemoryCacheOptions()));

        _context = new DefaultHttpContext();
        _context.Request.Path = "/products";
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_never_call_the_tenant_endpoint() => _handler.Calls.ShouldEqual(0);

    sealed class CountingTenantsHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("[]", Encoding.UTF8, "application/json")
            });
        }
    }
}
