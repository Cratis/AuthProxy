// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>A token signed with a key the provider does not publish is refused.</summary>
public class and_the_signature_is_not_from_the_providers_keys : an_upstream_access_token
{
    protected override SecurityKey SigningKey => OtherKey;

    async Task Because() => _result = await Validate(CreateAccessToken());

    [Fact] void should_refuse_the_token() => _result.ShouldBeNull();
}
