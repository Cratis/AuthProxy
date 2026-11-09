// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

public class when_a_pat_only_route_has_no_usable_realm : given_a_refusal
{
    HttpContext _noKey = default!;
    HttpContext _hostileKey = default!;

    async Task Because()
    {
        (_noKey, _) = await Write(BearerTokenValidationStatus.Missing, Route(BearerProfile.PatOnly));
        (_hostileKey, _) = await Write(BearerTokenValidationStatus.Missing, Route(BearerProfile.PatOnly, "x\", resource_metadata=\"https://evil.example"));
    }

    [Fact] void should_challenge_bare_without_a_key() => _noKey.Response.Headers.WWWAuthenticate.ToString().ShouldEqual("Bearer");
    [Fact] void should_challenge_bare_with_a_hostile_key() => _hostileKey.Response.Headers.WWWAuthenticate.ToString().ShouldEqual("Bearer");
}
