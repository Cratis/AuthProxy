// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_request_is_authentication_bootstrap : Specification
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

        _middleware = new TenantSelectionMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config,
            Substitute.For<ITenantResolver>(),
            Substitute.For<IHttpClientFactory>(),
            Substitute.For<IErrorPageProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/signin-scheme";
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
}
