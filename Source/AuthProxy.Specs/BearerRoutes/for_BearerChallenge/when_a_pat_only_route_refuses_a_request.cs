// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

public class when_a_pat_only_route_refuses_a_request : given_a_refusal
{
    HttpContext _missing = default!;
    HttpContext _invalid = default!;
    string _body = string.Empty;

    async Task Because()
    {
        (_missing, _body) = await Write(BearerTokenValidationStatus.Missing, Route(BearerProfile.PatOnly, "direct"));
        (_invalid, _) = await Write(BearerTokenValidationStatus.Invalid, Route(BearerProfile.PatOnly, "direct"));
    }

    [Fact] void should_be_unauthorized() => _missing.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_name_only_the_realm() => _missing.Response.Headers.WWWAuthenticate.ToString().ShouldEqual("Bearer realm=\"direct\"");
    [Fact] void should_name_only_the_realm_for_an_invalid_credential() => _invalid.Response.Headers.WWWAuthenticate.ToString().ShouldEqual("Bearer realm=\"direct\"");
    [Fact] void should_carry_the_unauthorized_error() => _body.ShouldEqual("{\"error\":\"unauthorized\"}");
}
