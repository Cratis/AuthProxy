// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_multiple_providers_are_configured;

public class when_multiple_providers_are_configured : Specification
{
    protected SelectProviderMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected bool _nextCalled;
    protected IErrorPageProvider _errorPageProvider;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider { Name = "Provider One", Authority = "https://a.example.com", ClientId = "c1" },
                new C.OidcProvider { Name = "Provider Two", Authority = "https://b.example.com", ClientId = "c2" }
            ]
        });

        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _errorPageProvider
            .WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>())
            .Returns(Task.CompletedTask);

        _middleware = new SelectProviderMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            authConfig,
            _errorPageProvider,
            Substitute.For<ITenantResolver>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
        _context.Response.Body = new System.IO.MemoryStream();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
