// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware.given;

public class a_tenant_selection_endpoint : Specification
{
    protected TenantSelectionMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected C.AuthProxy _authProxyConfig;
    protected IErrorPageProvider _errorPageProvider;
    protected bool _nextCalled;
    protected int _endpointCalls;
    protected HttpStatusCode? _endpointStatus;
    protected string _endpointBody = "[]";
    protected Exception _endpointFailure = new HttpRequestException("Tenant endpoint is unavailable");
    protected const string AnonymousPath = "/api/portal/report";
    protected const string Tenants2 = """[{"id":"tenant-a","name":"Tenant A"},{"id":"tenant-b","name":"Tenant B"}]""";

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        _authProxyConfig = new C.AuthProxy
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
        config.CurrentValue.Returns(_authProxyConfig);

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
            ResolverReflectingConfirmation(),
            httpClientFactory,
            _errorPageProvider,
            new MemoryCache(new MemoryCacheOptions()),
            given.signed_selected_tenant_cookies.Instance,
            Substitute.For<ILogger<TenantSelectionMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/products";
        _context.Request.Headers["Sec-Fetch-Dest"] = "document";
        _context.Response.Body = new MemoryStream();
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    static ITenantResolver ResolverReflectingConfirmation()
    {
        var resolver = Substitute.For<ITenantResolver>();
        resolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<TenantResolutionResult>())
            .Returns(callInfo =>
            {
                var confirmed = callInfo.Arg<HttpContext>().Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var tenant);
                callInfo[1] = new TenantResolutionResult(confirmed ? (string)tenant! : string.Empty, C.TenantSourceIdentifierResolverType.Selection);
                return confirmed;
            });
        return resolver;
    }

    protected void ServeAnonymousPath() =>
        _authProxyConfig.Services = new Dictionary<string, C.Service>
        {
            ["test"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" }, AnonymousPaths = [AnonymousPath] },
        };

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
