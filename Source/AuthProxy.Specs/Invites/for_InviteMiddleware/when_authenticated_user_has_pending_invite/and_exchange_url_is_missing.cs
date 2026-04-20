// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_authenticated_user_has_pending_invite;

public class and_exchange_url_is_missing : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    IHttpClientFactory _httpClientFactory;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();

        var config = new C.AuthProxy
        {
            Invite = new C.Invite()
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _httpClientFactory = Substitute.For<IHttpClientFactory>();

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            tokenValidator,
            optionsMonitor,
            CreateEmptyAuthConfig(),
            Substitute.For<ITenantResolver>(),
            _httpClientFactory,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";

        var identity = new ClaimsIdentity([new Claim("sub", "user-123")], "aad");
        _context.User = new ClaimsPrincipal(identity);
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-invite-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_delete_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
    [Fact] void should_not_call_exchange_endpoint() => _httpClientFactory.DidNotReceive().CreateClient(Arg.Any<string>());

    static IOptionsMonitor<C.Authentication> CreateEmptyAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(new C.Authentication());
        return monitor;
    }
}
