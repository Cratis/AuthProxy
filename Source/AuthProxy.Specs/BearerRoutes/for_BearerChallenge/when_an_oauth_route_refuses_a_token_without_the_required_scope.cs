// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

public class when_an_oauth_route_refuses_a_token_without_the_required_scope : given_a_refusal
{
    HttpContext _context = default!;
    string _body = string.Empty;

    async Task Because() => (_context, _body) = await Write(BearerTokenValidationStatus.InsufficientScope, Route(BearerProfile.OAuthOnly, scopes: ["mcp.read"]));

    [Fact] void should_be_forbidden() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_name_the_scope() => _context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual($"Bearer error=\"insufficient_scope\", scope=\"mcp.read\", resource_metadata=\"{MetadataUrl}\"");
    [Fact] void should_answer_with_json() => _context.Response.ContentType.ShouldEqual("application/json");
    [Fact] void should_carry_the_insufficient_scope_error() => _body.ShouldEqual("{\"error\":\"insufficient_scope\"}");
}
