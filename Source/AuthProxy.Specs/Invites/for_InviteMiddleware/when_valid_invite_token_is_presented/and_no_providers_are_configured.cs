// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_valid_invite_token_is_presented;

public class and_no_providers_are_configured : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;
    int _nextCallCount;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();
        tokenValidator.ValidateDetailed(Arg.Any<string>()).Returns(InviteTokenValidationResult.Valid);

        var config = new C.AuthProxy
        {
            Invite = new C.Invite { ExchangeUrl = "http://studio/internal/invites/exchange" }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var authConfigMonitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfigMonitor.CurrentValue.Returns(new C.Authentication());

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                _nextCallCount++;
                return Task.CompletedTask;
            },
            tokenValidator,
            optionsMonitor,
            authConfigMonitor,
            Substitute.For<IHttpClientFactory>(),
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/some-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_call_next_only_once() => _nextCallCount.ShouldEqual(1);
    [Fact] void should_set_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
}
