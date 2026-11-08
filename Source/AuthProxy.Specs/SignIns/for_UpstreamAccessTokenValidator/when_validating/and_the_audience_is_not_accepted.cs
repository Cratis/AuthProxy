// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>A token issued for another audience is refused.</summary>
public class and_the_audience_is_not_accepted : an_upstream_access_token
{
    protected override string TokenAudience => "another-client";

    async Task Because() => _result = await Validate(CreateAccessToken());

    [Fact] void should_refuse_the_token() => _result.ShouldBeNull();
}
