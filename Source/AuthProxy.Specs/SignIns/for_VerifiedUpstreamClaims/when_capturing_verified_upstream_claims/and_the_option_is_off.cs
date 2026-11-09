// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.given;

namespace Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.when_capturing_verified_upstream_claims;

/// <summary>With the option off the access token is not even examined, and nothing is recorded.</summary>
public class and_the_option_is_off : a_completed_code_exchange
{
    VerifiedUpstreamClaims? _claims;

    protected override bool IncludesClaims => false;

    async Task Because()
    {
        await VerifiedUpstreamClaims.Capture(_context, Scheme);
        _claims = VerifiedUpstreamClaims.For(_httpContext, Scheme);
    }

    [Fact] void should_record_no_claims() => _claims.ShouldBeNull();
}
