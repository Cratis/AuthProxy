// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.when_validating;

/// <summary>A token from another issuer than the one that issued the identity token is refused.</summary>
public class and_the_issuer_differs_from_the_identity_token : an_upstream_access_token
{
    protected override string TokenIssuer => "https://evil.example.com";

    async Task Because() => _result = await Validate(CreateAccessToken());

    [Fact] void should_refuse_the_token() => _result.ShouldBeNull();
}
