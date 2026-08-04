// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_selected_tenant_is_no_longer_available_for_the_user : Specification
{
    TenantSelectionMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

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
                callInfo[1] = new TenantResolutionResult("tenant-revoked", C.TenantSourceIdentifierResolverType.Selection);
                return true;
            });

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>())
            .Returns(new HttpClient(new FakeTenantsHandler()));

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
        _context.Request.QueryString = new QueryString("?view=list");
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_delete_the_selected_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenant}=;");
    [Fact] void should_delete_the_tenant_list_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenants}=;");
    [Fact] void should_replay_the_request_without_the_stale_tenant() => _context.Response.Headers.Location.ToString().ShouldEqual("/products?view=list");
    [Fact] void should_redirect() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();

    sealed class FakeTenantsHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """[{"id":"tenant-a","name":"Tenant A"},{"id":"tenant-b","name":"Tenant B"}]""",
                    Encoding.UTF8,
                    "application/json")
            });
    }
}
