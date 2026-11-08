// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>A token signed with a key the cached set lacks is accepted once, after one refreshed key set carries it.</summary>
public class and_the_provider_has_rotated_its_keys : an_upstream_access_token
{
    protected override SecurityKey SigningKey => OtherKey;

    protected override IReadOnlyCollection<SecurityKey> RotatedKeys => [OtherKey];

    async Task Because() => _result = await Validate(CreateAccessToken());

    [Fact] void should_accept_the_token() => _result.ShouldNotBeNull();
    [Fact] void should_refresh_the_keys_exactly_once() => _keyRequests.ShouldEqual([false, true]);
}
