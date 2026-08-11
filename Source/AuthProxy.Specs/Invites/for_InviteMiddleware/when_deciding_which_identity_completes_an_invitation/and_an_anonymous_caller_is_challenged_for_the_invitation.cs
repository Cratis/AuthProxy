// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_deciding_which_identity_completes_an_invitation;

/// <summary>
/// The other side of the same contract: the challenge started for an invitation carries that invitation's
/// capability, which is the only thing that lets the session coming back be recognized as the one this
/// invitation asked for. Without it every completed sign-in would be refused and no invitation could ever
/// be accepted.
/// </summary>
public class and_an_anonymous_caller_is_challenged_for_the_invitation : given.an_invitation_entry
{
    protected override IReadOnlyList<C.OidcProvider> Providers =>
    [
        new() { Name = "GitHub", Authority = "https://github.test", ClientId = "github-id", ClientSecret = "github-secret" }
    ];

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact]
    void should_bind_the_invitation_capability_to_the_challenge() =>
        _authenticationService.Received(1).ChallengeAsync(
            _context,
            OidcProviderScheme.FromName("GitHub"),
            Arg.Is<AuthenticationProperties>(properties =>
                properties.Items[InvitationAuthenticationState.CapabilityHashStateKey]
                    == InvitationAuthenticationState.ComputeCapabilityHash(Capability)));
}
