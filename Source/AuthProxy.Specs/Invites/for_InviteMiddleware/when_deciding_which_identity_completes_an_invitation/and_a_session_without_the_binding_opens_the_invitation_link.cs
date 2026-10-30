// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_deciding_which_identity_completes_an_invitation;

/// <summary>
/// A signed-in caller whose session carries no invitation binding — however recently it was issued — arrives on
/// the invitation link, as happens when the provider round-trip returns without the challenge properties. The
/// request ends on the provider selection page: nothing is exchanged, nothing is redirected and nothing is
/// challenged on the person's behalf, so the browser can never be bounced between the invitation and a provider.
/// </summary>
public class and_a_session_without_the_binding_opens_the_invitation_link : given.an_invitation_entry
{
    void Establish() => GivenASessionWithoutTheInvitationBinding();

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact]
    void should_end_the_request_on_the_provider_choice() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.InvitationSelectProvider,
            StatusCodes.Status200OK,
            Arg.Any<IReadOnlyDictionary<string, string>>());

    [Fact] void should_not_redirect() => _context.Response.Headers.Location.ToString().ShouldBeEmpty();
    [Fact] void should_keep_the_invitation_pending() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();

    [Fact]
    void should_not_start_a_challenge() =>
        _authenticationService.DidNotReceive().ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<AuthenticationProperties>());
}
