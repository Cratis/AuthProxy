// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_lobby_mode_is_configured;

public class and_unauthenticated_request_has_no_invite_token : given.lobby_mode_middleware
{
    void Establish() => _context.Request.Path = "/";

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_invitation_required_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.InvitationRequired,
            StatusCodes.Status401Unauthorized);
}
