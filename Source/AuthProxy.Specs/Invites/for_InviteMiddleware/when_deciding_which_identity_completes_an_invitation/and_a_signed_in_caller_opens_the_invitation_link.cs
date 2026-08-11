// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_deciding_which_identity_completes_an_invitation;

/// <summary>
/// The production case this exists for: somebody already signed in with one provider opens an invitation to
/// join an organization. They are offered the choice of provider, and nothing is exchanged with the session
/// they arrived carrying.
/// </summary>
public class and_a_signed_in_caller_opens_the_invitation_link : given.an_invitation_entry
{
    void Establish() => GivenAPreExistingSession();

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact]
    void should_offer_the_provider_choice() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.InvitationSelectProvider,
            StatusCodes.Status200OK);

    [Fact] void should_carry_the_invitation_across_the_choice() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
    [Fact] void should_offer_every_configured_provider() => _context.Response.Headers.SetCookie.ToString().ShouldContain("Google");
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
}
