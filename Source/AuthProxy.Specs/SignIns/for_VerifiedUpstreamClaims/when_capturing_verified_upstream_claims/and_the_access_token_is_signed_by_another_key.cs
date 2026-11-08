// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.when_capturing_verified_upstream_claims;

/// <summary>An access token that fails validation records no claims at all — the identity token's are not sent either.</summary>
public class and_the_access_token_is_signed_by_another_key : a_completed_code_exchange
{
    VerifiedUpstreamClaims? _claims;

    protected override SecurityKey AccessTokenKey => OtherKey;

    async Task Because()
    {
        await VerifiedUpstreamClaims.Capture(_context, Scheme);
        _claims = VerifiedUpstreamClaims.For(_httpContext, Scheme);
    }

    [Fact] void should_record_no_claims() => _claims.ShouldBeNull();
}
