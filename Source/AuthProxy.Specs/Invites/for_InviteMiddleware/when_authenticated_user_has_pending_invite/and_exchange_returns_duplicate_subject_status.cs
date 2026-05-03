// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_authenticated_user_has_pending_invite;

public class and_exchange_returns_duplicate_subject_status : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPageProvider;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();

        var config = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                ExchangeUrl = "http://studio/internal/invites/exchange"
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.Conflict)));

        _errorPageProvider = Substitute.For<IErrorPageProvider>();

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
            httpClientFactory,
            _errorPageProvider,
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";

        var identity = new ClaimsIdentity([new Claim("sub", "user-123")], "aad");
        _context.User = new ClaimsPrincipal(identity);
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-invite-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_delete_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
    [Fact]
    void should_serve_subject_already_exists_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.InvitationSubjectAlreadyExists,
            StatusCodes.Status409Conflict);

    static IOptionsMonitor<C.Authentication> CreateEmptyAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(new C.Authentication());
        return monitor;
    }
}
