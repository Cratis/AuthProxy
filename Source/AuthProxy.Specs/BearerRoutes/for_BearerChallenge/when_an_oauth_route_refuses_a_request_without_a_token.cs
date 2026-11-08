// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

public class when_an_oauth_route_refuses_a_request_without_a_token : given_a_refusal
{
    HttpContext _context = default!;
    string _body = string.Empty;

    async Task Because() => (_context, _body) = await Write(BearerTokenValidationStatus.Missing, Route(BearerProfile.OAuthOnly));

    [Fact] void should_be_unauthorized() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_challenge_with_the_resource_metadata() => _context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual($"Bearer resource_metadata=\"{MetadataUrl}\"");
    [Fact] void should_answer_with_json() => _context.Response.ContentType.ShouldEqual("application/json");
    [Fact] void should_carry_the_unauthorized_error() => _body.ShouldEqual("{\"error\":\"unauthorized\"}");
    [Fact] void should_not_be_cached() => _context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
    [Fact] void should_not_redirect() => _context.Response.Headers.ContainsKey("Location").ShouldBeFalse();
}
