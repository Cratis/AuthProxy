// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.given;

namespace Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.when_capturing_verified_upstream_claims;

/// <summary>The handler's validated-token event validates the access token from the same exchange and records its claims.</summary>
public class and_the_access_token_is_valid : a_completed_code_exchange
{
    VerifiedUpstreamClaims? _claims;

    async Task Because()
    {
        await VerifiedUpstreamClaims.Capture(_context, Scheme);
        _claims = VerifiedUpstreamClaims.For(_httpContext, Scheme);
    }

    [Fact] void should_record_claims() => _claims.ShouldNotBeNull();
    [Fact] void should_take_the_external_account_id_from_the_access_token() => _claims!.Values["github_id"].ShouldEqual("777");
    [Fact] void should_take_the_authentication_time_from_the_identity_token() => _claims!.Values["auth_time"].ShouldEqual(1700000000L);
}
