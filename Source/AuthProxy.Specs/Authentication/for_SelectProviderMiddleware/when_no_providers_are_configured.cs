// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware;

public class when_no_providers_are_configured : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication());

        _middleware = new SelectProviderMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            authConfig,
            Substitute.For<IErrorPageProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
}
