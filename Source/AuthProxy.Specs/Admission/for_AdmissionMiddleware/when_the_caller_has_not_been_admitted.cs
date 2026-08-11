// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionMiddleware;

/// <summary>
/// An unadmitted request is answered here and goes no further — not to the pages map, not to the static
/// files, not to routing, and not to anything that could tell the caller what exists.
/// </summary>
public class when_the_caller_has_not_been_admitted : given.an_admission_middleware
{
    void Establish() => BuildMiddleware();

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_let_the_request_reach_the_rest_of_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_answer_not_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
    [Fact] void should_answer_with_the_fixed_body() => WrittenBody().ShouldEqual(UniformDenial.Body);
    [Fact] void should_answer_with_the_fixed_content_type() => _context.Response.ContentType.ShouldEqual(UniformDenial.ContentType);
    [Fact] void should_issue_no_cookie() => _context.Response.Headers.SetCookie.Count.ShouldEqual(0);
    [Fact] void should_not_offer_a_challenge() => _context.Response.Headers.WWWAuthenticate.Count.ShouldEqual(0);
    [Fact] void should_not_name_the_methods_a_route_accepts() => _context.Response.Headers.Allow.Count.ShouldEqual(0);
    [Fact] void should_not_redirect_anywhere() => _context.Response.Headers.Location.Count.ShouldEqual(0);
}
