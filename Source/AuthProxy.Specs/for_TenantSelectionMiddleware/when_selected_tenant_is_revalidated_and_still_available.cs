// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_selected_tenant_is_revalidated_and_still_available : Specification
{
    TenantSelectionMiddleware _middleware;
    CountingTenantsHandler _handler;
    int _nextCalls;

    void Establish()
    {
        var authProxyConfig = new C.AuthProxy
        {
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
                _nextCalls++;
                return Task.CompletedTask;
            },
            config,
            tenantResolver,
            httpClientFactory,
            Substitute.For<IErrorPageProvider>(),
            new MemoryCache(new MemoryCacheOptions()));
    }

    async Task Because()
    {
        await _middleware.InvokeAsync(CreateContext());
        await _middleware.InvokeAsync(CreateContext());
    }

    [Fact] void should_call_next_for_both_requests() => _nextCalls.ShouldEqual(2);
    [Fact] void should_only_call_the_tenant_endpoint_once_within_the_revalidation_window() => _handler.Calls.ShouldEqual(1);

    static DefaultHttpContext CreateContext()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/products";
        context.Response.Body = new MemoryStream();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
        return context;
    }

    sealed class CountingTenantsHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """[{"id":"tenant-a","name":"Tenant A"},{"id":"tenant-b","name":"Tenant B"}]""",
                    Encoding.UTF8,
                    "application/json")
            });
        }
    }
}
