// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_activating_through_the_pipeline;

public class with_the_registered_invitation_lifecycle : given.an_invites_container
{
    void Establish() => AddCanonicalIdentityResolver();

    async Task Because() => await RunPipeline(_ => _.UseInviteMiddleware());

    [Fact] void should_reach_the_next_middleware() => _reachedNext.ShouldBeTrue();
}
