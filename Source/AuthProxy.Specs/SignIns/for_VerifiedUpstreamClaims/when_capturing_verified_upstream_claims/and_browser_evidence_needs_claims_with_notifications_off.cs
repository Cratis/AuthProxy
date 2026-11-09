// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.given;

namespace Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.when_capturing_verified_upstream_claims;

public class and_browser_evidence_needs_claims_with_notifications_off : a_completed_code_exchange
{
    protected override bool IncludesClaims => false;

    async Task Because() => await VerifiedUpstreamClaims.Capture(_context, Scheme, sessionEvidence: true);

    [Fact] void should_capture_the_verified_realm_issuer() => VerifiedUpstreamClaims.For(_httpContext, Scheme)!.Values["iss"].ShouldEqual(Issuer);
    [Fact] void should_capture_the_verified_original_authentication_time() => VerifiedUpstreamClaims.For(_httpContext, Scheme)!.Values["auth_time"].ShouldEqual(1700000000L);
}
