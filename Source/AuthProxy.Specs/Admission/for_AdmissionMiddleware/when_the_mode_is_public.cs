// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionMiddleware;

/// <summary>
/// A deployment that never opted in is left entirely alone. The middleware is on the pipeline of every
/// deployment, so "changes nothing" has to mean the request is handed on before anything about a cookie,
/// a path or a capability is even looked at.
/// </summary>
public class when_the_mode_is_public : given.an_admission_middleware
{
    void Establish()
    {
        _config.Admission = new C.Admission();
        _context.Request.Path = "/.cratis/providers";
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_leave_the_request_to_the_rest_of_the_pipeline() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_answer_the_request_itself() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_write_nothing() => WrittenBody().ShouldBeEmpty();
    [Fact] void should_not_look_for_a_capability() => _admission.DidNotReceiveWithAnyArgs().TryAdmit(default!, default!);
}
