// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionMiddleware.when_a_capability_is_presented;

/// <summary>
/// The presentation is answered by the admission handler and never handed downstream — the endpoint exists
/// to issue an entry, not to reach anything behind the proxy.
/// </summary>
public class and_it_admits : given.an_admission_middleware
{
    void Establish()
    {
        _context.Request.Path = "/.cratis/admission";
        _context.Request.Method = HttpMethods.Post;
        _admission.TryAdmit(_context, _config).Returns(true);
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_have_the_presentation_handled() => _admission.Received(1).TryAdmit(_context, _config);
    [Fact] void should_not_hand_the_presentation_downstream() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_refuse_it() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_write_no_refusal() => WrittenBody().ShouldBeEmpty();
}
