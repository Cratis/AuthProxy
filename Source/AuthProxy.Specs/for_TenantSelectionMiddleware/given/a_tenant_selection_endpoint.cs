// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware.given;

public class a_tenant_selection_endpoint : Specification
{
    protected TenantSelectionMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected IErrorPageProvider _errorPageProvider;
    protected bool _nextCalled;
    protected int _endpointCalls;
    protected HttpStatusCode? _endpointStatus;
    protected string _endpointBody = "[]";
    protected Exception _endpointFailure = new HttpRequestException("Tenant endpoint is unavailable");

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy
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
        });

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new TenantsHandler(this)));

        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _errorPageProvider.WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>())
            .Returns(callInfo =>
            {
                callInfo.Arg<HttpContext>().Response.StatusCode = callInfo.Arg<int>();
                return Task.CompletedTask;
            });

        _middleware = new TenantSelectionMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config,
            Substitute.For<ITenantResolver>(),
            httpClientFactory,
            _errorPageProvider,
            new MemoryCache(new MemoryCacheOptions()),
            Substitute.For<ILogger<TenantSelectionMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/products";
        _context.Request.Headers["Sec-Fetch-Dest"] = "document";
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    sealed class TenantsHandler(a_tenant_selection_endpoint specification) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            specification._endpointCalls++;
            return specification._endpointStatus is { } status
                ? Task.FromResult(new HttpResponseMessage(status)
                {
                    Content = new StringContent(specification._endpointBody)
                })
                : Task.FromException<HttpResponseMessage>(specification._endpointFailure);
        }
    }
}
