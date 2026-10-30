// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_activating_through_the_pipeline;

/// <summary>
/// Pins the released fallback: without a canonical identity resolver the eight-argument constructor activates.
/// <c language="text">ActivatorUtilities</c> chooses the longest constructor it can satisfy and throws when two
/// satisfiable constructors share that length, so a second eight-argument constructor would break this container.
/// </summary>
public class without_the_canonical_identity_resolver : given.an_invites_container
{
    async Task Because() => await RunPipeline(_ => _.UseMiddleware<InviteMiddleware>());

    [Fact] void should_reach_the_next_middleware() => _reachedNext.ShouldBeTrue();
}
