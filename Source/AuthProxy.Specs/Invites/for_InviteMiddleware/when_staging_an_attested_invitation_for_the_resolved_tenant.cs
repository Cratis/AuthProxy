// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_staging_an_attested_invitation_for_the_resolved_tenant : given.an_attested_invitation_staging
{
    void Establish() => _context.Items[TenancyMiddleware.TenantIdItemKey] = TenantId;

    async Task Because() => await ((InviteMiddleware)_context.Items["middleware"]!).InvokeAsync(_context);

    [Fact] void should_call_the_stage_endpoint() => _handler.Request.ShouldNotBeNull();
    [Fact] void should_challenge_the_capability_provider() => _authenticationService.Received(1).ChallengeAsync(_context, OidcProviderScheme.FromName("First"), Arg.Any<AuthenticationProperties?>());
}
