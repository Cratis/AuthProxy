// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_staging_an_attested_invitation_for_another_tenant : given.an_attested_invitation_staging
{
    void Establish() => _context.Items[TenancyMiddleware.TenantIdItemKey] = "another-tenant";

    async Task Because() => await ((InviteMiddleware)_context.Items["middleware"]!).InvokeAsync(_context);

    [Fact] void should_answer_invitation_invalid_with_unauthorized() => _errorPages.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationInvalid, StatusCodes.Status401Unauthorized);
    [Fact] void should_not_call_the_stage_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_protect_an_entry_state() => _protector.State.ShouldBeNull();
    [Fact] void should_not_challenge() => _authenticationService.DidNotReceive().ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<AuthenticationProperties?>());
    [Fact] void should_not_continue() => _nextCalled.ShouldBeFalse();
}
