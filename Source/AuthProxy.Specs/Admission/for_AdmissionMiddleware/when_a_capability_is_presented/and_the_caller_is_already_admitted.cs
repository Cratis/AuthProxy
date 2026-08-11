// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionMiddleware.when_a_capability_is_presented;

/// <summary>
/// A presentation is answered by the admission handler even when the browser making it is already admitted.
/// The order of the two questions is load-bearing and this is the only spec that says so.
/// </summary>
/// <remarks>
/// Asking "is this caller admitted" first reads as harmless and is not. An admitted browser posting to the
/// presentation path would be handed downstream, no endpoint would match it, and the reverse proxy's
/// catch-all route would forward the request — capability in the body — to the backend service. The body-only
/// rule exists precisely so that a bearer value never lands in an access log, a cache key or a browser
/// history, and forwarding it to an application puts it in the first of those.
/// <para>
/// Every other spec in this folder presents without an entry transaction or holds one without presenting, so
/// the two blocks are never both live at once and swapping them changes nothing any of them observes.
/// </para>
/// </remarks>
public class and_the_caller_is_already_admitted : given.an_admission_middleware
{
    void Establish()
    {
        _context.Request.Path = "/.cratis/admission";
        _context.Request.Method = HttpMethods.Post;
        PresentingALiveEntryTransaction();
        _admission.TryAdmit(_context, _config).Returns(true);
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_have_the_presentation_handled() => _admission.Received(1).TryAdmit(_context, _config);
    [Fact] void should_not_hand_the_presentation_downstream() => _nextCalled.ShouldBeFalse();
}
