// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_invite_token_is_re_validated_at_exchange;

public class and_token_has_wrong_issuer : given.an_invite_exchange
{
    void Establish()
    {
        GivenAuthenticatedUserWith();
        GivenPendingInviteCookie(CreateSignedToken(issuer: "https://evil.example.com"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeFalse();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_invitation_invalid_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationInvalid, StatusCodes.Status401Unauthorized);
}
