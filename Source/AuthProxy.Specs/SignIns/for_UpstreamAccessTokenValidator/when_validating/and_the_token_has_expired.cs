// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>An expired token is refused.</summary>
public class and_the_token_has_expired : an_upstream_access_token
{
    protected override DateTime Expires => DateTime.UtcNow.AddMinutes(-10);

    protected override DateTime? NotBefore => DateTime.UtcNow.AddMinutes(-20);

    async Task Because() => _result = await Validate(CreateAccessToken());

    [Fact] void should_refuse_the_token() => _result.ShouldBeNull();
}
