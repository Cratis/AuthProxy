// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.given;

namespace Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.when_capturing_verified_upstream_claims;

/// <summary>A token response without an access token records no claims.</summary>
public class and_the_token_response_has_no_access_token : a_completed_code_exchange
{
    VerifiedUpstreamClaims? _claims;

    protected override bool ReturnsAccessToken => false;

    async Task Because()
    {
        await VerifiedUpstreamClaims.Capture(_context, Scheme);
        _claims = VerifiedUpstreamClaims.For(_httpContext, Scheme);
    }

    [Fact] void should_record_no_claims() => _claims.ShouldBeNull();
}
