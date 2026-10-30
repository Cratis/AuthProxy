// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_staging_an_attested_invitation : given.an_attested_invitation_staging
{
    async Task Because() => await ((InviteMiddleware)_context.Items["middleware"]!).InvokeAsync(_context);

    [Fact] void should_authenticate_the_stage_call() => _handler.Request!.Headers.Authorization!.Parameter.ShouldEqual("stage-attestation");
    [Fact] void should_send_the_exact_invitation_capability() => BodyProperty("invitationToken").ShouldEqual(_token);
    [Fact] void should_send_the_authproxy_transaction() => BodyProperty("invitationTransaction").ShouldEqual(_protector.State!.InvitationTransaction);
    [Fact] void should_send_the_independent_challenge() => BodyProperty("invitationChallenge").ShouldEqual(_protector.State!.InvitationChallenge);
    [Fact] void should_not_send_identity_authority() => _handler.Body.ShouldNotContain("provider");
    [Fact] void should_protect_the_staged_state_for_the_provider_round_trip() => _protector.State.ShouldNotBeNull();
    [Fact] void should_allow_only_the_provider_named_by_the_signed_capability() => _authenticationService.Received(1).ChallengeAsync(_context, OidcProviderScheme.FromName("First"), Arg.Any<AuthenticationProperties?>());
    [Fact] void should_not_offer_another_provider() => _authenticationService.DidNotReceive().ChallengeAsync(_context, OidcProviderScheme.FromName("Second"), Arg.Any<AuthenticationProperties?>());
    [Fact] void should_not_continue_before_provider_selection() => _nextCalled.ShouldBeFalse();
}
