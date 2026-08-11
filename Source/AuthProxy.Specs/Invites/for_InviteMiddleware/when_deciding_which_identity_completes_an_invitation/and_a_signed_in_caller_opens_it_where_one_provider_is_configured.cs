// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_deciding_which_identity_completes_an_invitation;

/// <summary>
/// With one provider configured there is nothing to choose between, yet a caller who already has a session
/// is still shown the page rather than challenged straight through. The page names the account the
/// organization is about to be bound to and makes the person act on it, and — being a terminal response —
/// it cannot become a redirect loop if a deployment's invitation binding fails to survive the provider
/// round-trip.
/// </summary>
public class and_a_signed_in_caller_opens_it_where_one_provider_is_configured : given.an_invitation_entry
{
    protected override IReadOnlyList<C.OidcProvider> Providers =>
    [
        new() { Name = "GitHub", Authority = "https://github.test", ClientId = "github-id", ClientSecret = "github-secret" }
    ];

    void Establish() => GivenAPreExistingSession();

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact]
    void should_offer_the_provider_choice() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.InvitationSelectProvider,
            StatusCodes.Status200OK);

    [Fact]
    void should_not_challenge_the_provider_silently() =>
        _authenticationService.DidNotReceive().ChallengeAsync(
            Arg.Any<HttpContext>(),
            Arg.Any<string>(),
            Arg.Any<AuthenticationProperties>());
}
