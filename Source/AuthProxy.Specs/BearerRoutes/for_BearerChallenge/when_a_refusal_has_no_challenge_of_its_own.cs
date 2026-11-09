// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

public class when_a_refusal_has_no_challenge_of_its_own : given_a_refusal
{
    HttpContext _forbidden = default!;
    HttpContext _badRequest = default!;
    string _forbiddenBody = string.Empty;
    string _badRequestBody = string.Empty;

    async Task Because()
    {
        (_forbidden, _forbiddenBody) = await Write(BearerTokenValidationStatus.MissingTenant, Route(BearerProfile.OAuthOnly));
        _badRequest = new DefaultHttpContext();
        var stream = new MemoryStream();
        _badRequest.Response.Body = stream;
        BearerChallenge.BadRequest(_badRequest);
        await _badRequest.Response.BodyWriter.FlushAsync();
        _badRequestBody = Encoding.UTF8.GetString(stream.ToArray());
    }

    [Fact] void should_forbid() => _forbidden.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_carry_a_forbidden_error() => _forbiddenBody.ShouldEqual("{\"error\":\"forbidden\"}");
    [Fact] void should_reject_a_bad_request() => _badRequest.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
    [Fact] void should_carry_an_invalid_request_error() => _badRequestBody.ShouldEqual("{\"error\":\"invalid_request\"}");
    [Fact] void should_answer_a_bad_request_with_json() => _badRequest.Response.ContentType.ShouldEqual("application/json");
    [Fact] void should_not_cache_a_bad_request() => _badRequest.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
}
