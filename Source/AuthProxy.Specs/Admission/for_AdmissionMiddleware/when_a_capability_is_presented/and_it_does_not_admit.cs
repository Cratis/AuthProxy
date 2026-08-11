// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionMiddleware.when_a_capability_is_presented;

/// <summary>
/// A presentation that does not admit is answered with the same refusal every other request gets, so the
/// admission endpoint is not itself a probe for whether the mode is on.
/// </summary>
public class and_it_does_not_admit : given.an_admission_middleware
{
    void Establish()
    {
        _context.Request.Path = "/.cratis/admission";
        _context.Request.Method = HttpMethods.Post;
        _admission.TryAdmit(_context, _config).Returns(false);
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_hand_the_presentation_downstream() => _nextCalled.ShouldBeFalse();
    [Fact] void should_answer_not_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
    [Fact] void should_answer_with_the_fixed_body() => WrittenBody().ShouldEqual(UniformDenial.Body);
    [Fact] void should_issue_no_cookie() => _context.Response.Headers.SetCookie.Count.ShouldEqual(0);
}
