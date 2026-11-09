// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>A token endpoint response without an access token yields nothing, and the provider is not even asked for keys.</summary>
public class and_there_is_no_access_token : an_upstream_access_token
{
    async Task Because() => _result = await Validate(null);

    [Fact] void should_yield_no_token() => _result.ShouldBeNull();
    [Fact] void should_not_ask_for_keys() => _keyRequests.ShouldBeEmpty();
}
