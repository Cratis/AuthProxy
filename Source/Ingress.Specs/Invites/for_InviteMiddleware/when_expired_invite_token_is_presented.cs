// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Invites.for_InviteMiddleware;

public class when_expired_invite_token_is_presented : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPageProvider;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();
        tokenValidator.ValidateDetailed(Arg.Any<string>()).Returns(InviteTokenValidationResult.Expired);

        var config = new IngressConfig();
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

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
            Substitute.For<IHttpClientFactory>(),
            _errorPageProvider,
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/expired-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_invitation_expired_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.InvitationExpired,
            StatusCodes.Status401Unauthorized);

    static IOptionsMonitor<AuthenticationConfig> CreateEmptyAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<AuthenticationConfig>>();
        monitor.CurrentValue.Returns(new AuthenticationConfig());
        return monitor;
    }
}
