// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_logging_identity_resolution;

/// <summary>
/// Specifies that a canonical memory-cache hit does not log raw canonical identity components.
/// </summary>
public class with_a_canonical_cache_hit : an_identity_details_resolver_with_recorded_logs
{
    async Task Because()
    {
        var resolver = CreateResolver();
        var principal = CanonicalPrincipal();
        await resolver.Resolve(new DefaultHttpContext(), principal, TenantId);
        await resolver.Resolve(new DefaultHttpContext(), principal, TenantId);
    }

    [Fact] void should_not_disclose_the_canonical_identity() => ShouldNotContainCanonicalIdentity();
}
