// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;

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
            Substitute.For<IErrorPageProvider>(),
            new MemoryCache(new MemoryCacheOptions()),
            given.signed_selected_tenant_cookies.Instance,
            Substitute.For<ILogger<TenantSelectionMiddleware>>(),
            Substitute.For<ForwardedIdentity.IForwardedIdentitySigner>());

        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(new C.Authentication { OidcProviders = [new() { Name = "Scheme" }] });
        _context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddSingleton(authentication).BuildServiceProvider()
        };
        _context.Request.Path = "/signin-scheme";
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "user-id")], "aad"));
    }

    void Destroy() => (_context.RequestServices as IDisposable)?.Dispose();

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
}
