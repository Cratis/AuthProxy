// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_authenticated_user_has_no_resolved_tenant_and_selection_strategy_is_configured : Specification
{
    TenantSelectionMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPageProvider;
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
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>()).Returns(false);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>())
            .Returns(new HttpClient(new FakeTenantsHandler()));

        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _errorPageProvider
            .WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>())
            .Returns(Task.CompletedTask);

        _middleware = new TenantSelectionMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config,
            tenantResolver,
            httpClientFactory,
            _errorPageProvider);

        _context = new DefaultHttpContext();
        _context.Request.Path = "/products";
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_set_tenants_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.Tenants);
    [Fact] void should_serve_select_tenant_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.SelectTenant, StatusCodes.Status200OK);
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
