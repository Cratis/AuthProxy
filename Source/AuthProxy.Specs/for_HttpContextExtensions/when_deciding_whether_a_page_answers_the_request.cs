// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_HttpContextExtensions;

/// <summary>
/// An HTML page is only an answer to a caller that is navigating to one. Everything else — a webhook, an
/// integration, a <c>fetch()</c> from the application's own frontend — is asking for data, and answering it
/// with a page is what turns a refusal into a recorded success.
/// <para>
/// <c>Sec-Fetch-Dest</c> is the deciding signal because it is the only one that separates a document
/// navigation from a scripted request: both arrive from the same browser, on the same connection, and
/// <c>fetch()</c> sends <c>Accept: *&#47;*</c>, which a naive read of <c>Accept</c> treats as "any content
/// type will do — including HTML". That read is exactly the defect. Only when the header is absent
/// entirely (a client predating Fetch Metadata) does <c>Accept</c> decide, and then only an explicit
/// <c>text/html</c> counts.
/// </para>
/// </summary>
public class when_deciding_whether_a_page_answers_the_request : Specification
{
    static HttpContext WithFetchDestination(string destination)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["Sec-Fetch-Dest"] = destination;
        return context;
    }

    static HttpContext WithAccept(string accept)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Accept = accept;
        return context;
    }

    [Fact] void should_answer_a_document_navigation_with_a_page() =>
        WithFetchDestination("document").IsDocumentNavigation().ShouldBeTrue();

    [Fact] void should_answer_a_framed_document_with_a_page() =>
        WithFetchDestination("iframe").IsDocumentNavigation().ShouldBeTrue();

    [Fact] void should_ignore_the_casing_of_the_destination() =>
        WithFetchDestination("Document").IsDocumentNavigation().ShouldBeTrue();

    [Fact] void should_not_answer_a_scripted_request_with_a_page() =>
        WithFetchDestination("empty").IsDocumentNavigation().ShouldBeFalse();

    [Fact] void should_not_answer_a_subresource_with_a_page() =>
        WithFetchDestination("script").IsDocumentNavigation().ShouldBeFalse();

    [Fact] void should_not_answer_a_wildcard_accept_from_a_script_with_a_page()
    {
        // The case the whole rule exists for: a fetch() carries Accept: */* and Sec-Fetch-Dest: empty.
        // Reading Accept alone would call this a browser and serve it the page.
        var context = new DefaultHttpContext();
        context.Request.Headers["Sec-Fetch-Dest"] = "empty";
        context.Request.Headers.Accept = "*/*";
        context.IsDocumentNavigation().ShouldBeFalse();
    }

    [Fact] void should_answer_an_explicit_html_accept_with_a_page() =>
        WithAccept("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8").IsDocumentNavigation().ShouldBeTrue();

    [Fact] void should_not_answer_a_wildcard_accept_with_a_page() =>
        WithAccept("*/*").IsDocumentNavigation().ShouldBeFalse();

    [Fact] void should_not_answer_a_json_accept_with_a_page() =>
        WithAccept("application/json").IsDocumentNavigation().ShouldBeFalse();

    [Fact] void should_not_answer_a_contradictory_destination_with_a_page()
    {
        // A request carrying the header twice is malformed — no browser sends it — so it decides nothing
        // and the request is refused. Every rejection in this classification falls the same way: an
        // unrecognized signal means "not navigating", never "serve the page anyway".
        var context = new DefaultHttpContext();
        context.Request.Headers["Sec-Fetch-Dest"] = new Microsoft.Extensions.Primitives.StringValues(["document", "empty"]);
        context.Request.Headers.Accept = "text/html";
        context.IsDocumentNavigation().ShouldBeFalse();
    }

    [Fact] void should_not_answer_a_request_stating_nothing_with_a_page() =>
        new DefaultHttpContext().IsDocumentNavigation().ShouldBeFalse();
}
