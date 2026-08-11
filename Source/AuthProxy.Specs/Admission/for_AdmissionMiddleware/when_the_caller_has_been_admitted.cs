// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Admission.for_AdmissionMiddleware;

/// <summary>
/// An admitted browser is handed on untouched, so everything downstream behaves exactly as it does in a
/// deployment that never closed the door — except that the answer says it was the cookie that earned it.
/// </summary>
public class when_the_caller_has_been_admitted : given.an_admission_middleware
{
    void Establish()
    {
        PresentingALiveEntryTransaction();
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_leave_the_request_to_the_rest_of_the_pipeline() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_answer_the_request_itself() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_write_nothing() => WrittenBody().ShouldBeEmpty();

    /// <summary>
    /// Without this a shared cache stores the answer under a key with no cookie in it and hands it to
    /// callers who presented none — serving the provider list, the selection page and the assets this mode
    /// exists to keep from being discoverable.
    /// </summary>
    [Fact]
    void should_say_the_answer_depends_on_the_entry_cookie() =>
        _context.Response.Headers[HeaderNames.Vary].ToString().ShouldEqual(HeaderNames.Cookie);
}
