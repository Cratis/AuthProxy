// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

/// <summary>
/// A path declared anonymous must be forwarded even when the caller <em>is</em> authenticated but has no
/// resolved tenant.
/// <para>
/// Skipping provider selection and the unresolved-tenant refusal only covers callers with no session at
/// all. A signed-in user with no tenant cookie who requests a declared anonymous path reaches tenant
/// selection instead, and is answered with the tenant-selection page at <c>200</c> — the same HTML-instead
/// -of-data, success-instead-of-refusal shape the anonymous path exists to remove, one middleware further
/// down. A declared path has to be reachable for every caller, not only for the signed-out ones.
/// </para>
/// </summary>
public class when_path_is_anonymous : Specification
{
    const string AnonymousPath = "/api/portal/report";

    TenantSelectionMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPageProvider;
    bool _nextCalled;

    void Establish()
    {
        var authProxyConfig = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["test"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                    AnonymousPaths = [AnonymousPath],
                },
            },
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
        _context.Request.Path = AnonymousPath;
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_serve_the_tenant_selection_page() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
    [Fact] void should_not_set_the_tenants_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.Tenants);

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
