// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

public class when_a_head_request_is_refused : given_a_refusal
{
    HttpContext _context = default!;
    string _body = "unset";

    async Task Because() => (_context, _body) = await Write(BearerTokenValidationStatus.Missing, Route(BearerProfile.OAuthOnly), "HEAD");

    [Fact] void should_be_unauthorized() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_still_challenge() => _context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual($"Bearer resource_metadata=\"{MetadataUrl}\"");
    [Fact] void should_send_no_body() => _body.ShouldEqual(string.Empty);
}
