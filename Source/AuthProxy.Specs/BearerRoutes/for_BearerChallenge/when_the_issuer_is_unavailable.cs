// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

public class when_the_issuer_is_unavailable : given_a_refusal
{
    HttpContext _context = default!;
    string _body = string.Empty;

    async Task Because() => (_context, _body) = await Write(BearerTokenValidationStatus.IssuerUnavailable, Route(BearerProfile.OAuthOnly));

    [Fact] void should_be_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_ask_the_client_to_retry() => _context.Response.Headers.RetryAfter.ToString().ShouldEqual("30");
    [Fact] void should_answer_with_json() => _context.Response.ContentType.ShouldEqual("application/json");
    [Fact] void should_carry_a_machine_readable_error() => _body.ShouldEqual("{\"error\":\"service_unavailable\"}");
    [Fact] void should_not_challenge() => _context.Response.Headers.ContainsKey("WWW-Authenticate").ShouldBeFalse();
}
