// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

public class when_an_oauth_route_refuses_an_invalid_token : given_a_refusal
{
    HttpContext _context = default!;
    string _body = string.Empty;

    async Task Because() => (_context, _body) = await Write(BearerTokenValidationStatus.Invalid, Route(BearerProfile.Combined));

    [Fact] void should_be_unauthorized() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_name_the_error_and_the_resource_metadata() => _context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"");
    [Fact] void should_carry_the_unauthorized_error() => _body.ShouldEqual("{\"error\":\"unauthorized\"}");
}
