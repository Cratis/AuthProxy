// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_logging_identity_resolution;

/// <summary>
/// Specifies that a case-varied reserved claim set does not disclose identity components through logs.
/// </summary>
public class with_a_case_varied_reserved_claim_set : an_identity_details_resolver_with_recorded_logs
{
    async Task Because() => await CreateResolver().Resolve(
        new DefaultHttpContext(),
        CanonicalPrincipal(
        [
            Claim(CanonicalIdentityClaims.ProviderKey.ToUpperInvariant(), ProviderKey),
            Claim(CanonicalIdentityClaims.Issuer, Issuer),
            Claim(CanonicalIdentityClaims.Subject, Subject)
        ]),
        TenantId);

    [Fact] void should_not_disclose_the_malformed_canonical_identity() => ShouldNotContainCanonicalIdentity();
}
