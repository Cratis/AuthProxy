// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_switching_to_a_tenant_that_is_not_a_member : Specification
{
    TenantSelectionMiddleware _middleware;
    DefaultHttpContext _context;

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

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>())
            .Returns(new HttpClient(new FakeTenantsHandler()));

        _middleware = new TenantSelectionMiddleware(
            _ => Task.CompletedTask,
            config,
            Substitute.For<ITenantResolver>(),
            httpClientFactory,
            Substitute.For<IErrorPageProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = WellKnownPaths.SelectTenant;
        _context.Request.QueryString = new QueryString("?tenantId=tenant-c&returnUrl=%2Fdashboard");
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_reject_the_selection() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
    [Fact] void should_not_set_the_selected_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.Tenant);

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
