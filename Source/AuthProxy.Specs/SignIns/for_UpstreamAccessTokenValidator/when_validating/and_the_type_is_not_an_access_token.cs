// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>A token that is not typed as an access token (an identity token, for one) is refused.</summary>
public class and_the_type_is_not_an_access_token : an_upstream_access_token
{
    protected override string TokenType => "JWT";

    async Task Because() => _result = await Validate(CreateAccessToken());

    [Fact] void should_refuse_the_token() => _result.ShouldBeNull();
}
