// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_selected_tenant_cannot_be_revalidated_because_the_endpoint_is_unavailable : Specification
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
                callInfo[1] = new TenantResolutionResult("tenant-a", C.TenantSourceIdentifierResolverType.Selection);
                return true;
            });

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>())
            .Returns(new HttpClient(new ThrowingTenantsHandler()));

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
            new MemoryCache(new MemoryCacheOptions()),
            given.signed_selected_tenant_cookies.Instance,
            Substitute.For<ILogger<TenantSelectionMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/products";
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
        given.signed_selected_tenant_cookies.Seed(_context, "tenant-a");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_answer_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_delete_the_selected_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain($"{Cookies.Tenant}=;");

    sealed class ThrowingTenantsHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("Tenant endpoint is unavailable");
    }
}
