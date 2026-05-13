// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_lobby_mode_is_configured;

public class and_request_is_on_invite_path : given.lobby_mode_middleware
{
    void Establish() => _context.Request.Path = "/invite/some-token";

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_serve_invitation_required_page() =>
        _errorPageProvider.DidNotReceive().WriteErrorPageAsync(
            Arg.Any<HttpContext>(),
            WellKnownPageNames.InvitationRequired,
            Arg.Any<int>());
}
