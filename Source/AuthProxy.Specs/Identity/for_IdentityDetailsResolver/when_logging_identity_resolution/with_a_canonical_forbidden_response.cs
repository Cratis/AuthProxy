// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_logging_identity_resolution;

/// <summary>
/// Specifies that a forbidden canonical resolution does not log raw canonical identity components.
/// </summary>
public class with_a_canonical_forbidden_response : an_identity_details_resolver_with_recorded_logs
{
    async Task Because() => await CreateResolver(HttpStatusCode.Forbidden).Resolve(new DefaultHttpContext(), CanonicalPrincipal(), TenantId);

    [Fact] void should_not_disclose_the_canonical_identity() => ShouldNotContainCanonicalIdentity();
}
