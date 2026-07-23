// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_request_is_not_a_logout : Specification
{
    LogoutMiddleware _middleware;
    DefaultHttpContext _context;
    IAuthenticationService _authenticationService;
    bool _nextCalled;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());

        _middleware = new LogoutMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config);

        _context = new DefaultHttpContext();
        _context.Request.Path = "/products";
        _context.Response.Body = new MemoryStream();

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_sign_out() => _authenticationService.DidNotReceive().SignOutAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<AuthenticationProperties>());
    [Fact] void should_not_clear_any_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldBeEmpty();
}
