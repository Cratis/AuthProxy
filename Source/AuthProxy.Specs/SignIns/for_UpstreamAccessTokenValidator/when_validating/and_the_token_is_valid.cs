// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>A correctly signed, unexpired access token of the right type, issuer and audience is accepted.</summary>
public class and_the_token_is_valid : an_upstream_access_token
{
    async Task Because() => _result = await Validate(CreateAccessToken());

    [Fact] void should_accept_the_token() => _result.ShouldNotBeNull();
    [Fact] void should_expose_its_claims() => _result!.Claims.Single(_ => _.Type == "github_id").Value.ShouldEqual("777");
    [Fact] void should_not_ask_for_refreshed_keys() => _keyRequests.ShouldEqual([false]);
}
