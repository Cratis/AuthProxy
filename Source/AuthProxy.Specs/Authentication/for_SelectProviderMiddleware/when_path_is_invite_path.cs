// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware;

public class when_path_is_invite_path : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider { Name = "p1", Authority = "https://a.example.com", ClientId = "c1" },
                new C.OidcProvider { Name = "p2", Authority = "https://b.example.com", ClientId = "c2" }
            ]
        });

        _middleware = new SelectProviderMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            authConfig,
            Substitute.For<IErrorPageProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/some-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_write_response() => _context.Response.StatusCode.ShouldEqual(200);
}
