// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_invite_path_is_missing_token : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        _middleware = new InviteMiddleware(
            _ => Task.CompletedTask,
            Substitute.For<IInviteTokenValidator>(),
            CreateAuthProxyConfig(),
            CreateAuthConfig(),
            Substitute.For<ITenantResolver>(),
            Substitute.For<IHttpClientFactory>(),
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/";
    }

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact]
    void should_return_bad_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);

    static IOptionsMonitor<C.AuthProxy> CreateAuthProxyConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy());
        return monitor;
    }

    static IOptionsMonitor<C.Authentication> CreateAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(new C.Authentication());
        return monitor;
    }
}
