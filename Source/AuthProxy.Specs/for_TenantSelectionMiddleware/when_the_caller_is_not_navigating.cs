// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

/// <summary>
/// The tenant-selection page is served at <c>200</c> exactly as the provider-selection page was, and it is
/// the same defect: a caller that is not navigating to a document reads it as a delivered success.
/// <para>
/// This one is reached by a caller that <em>is</em> authenticated, so it is the shape an already-signed-in
/// frontend hits — a <c>fetch()</c> for data that comes back as a tenant chooser with <c>response.ok</c>
/// true. It gets <c>403</c> rather than <c>401</c>: the caller is authenticated, and answering <c>401</c>
/// would tell a frontend to restart a login it has already completed, which is the loop
/// <c>TenancyMiddleware</c> already avoids for the no-organization case.
/// </para>
/// </summary>
public class when_the_caller_is_not_navigating : Specification
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
        _context.Request.Path = "/api/orders";
        _context.Request.Headers["Sec-Fetch-Dest"] = "empty";
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_not_serve_the_tenant_selection_page() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
    [Fact] void should_not_set_the_tenants_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.Tenants);
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
