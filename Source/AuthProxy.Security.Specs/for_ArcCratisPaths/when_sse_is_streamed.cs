// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Specifications;

namespace Cratis.AuthProxy.Security.for_ArcCratisPaths;

[Collection(ArcCratisSpecCollection.Name)]
public class when_sse_is_streamed(ArcCratisHarness harness) : given.an_arc_proxy(harness)
{
    string _first;
    string _second;
    string _contentType;
    HttpStatusCode _status;
    ForwardedRequest _forwarded;

    async Task Because()
    {
        using var request = Request("/.cratis/queries/sse");
        request.Headers.Accept.ParseAdd("text/event-stream");
        using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Deadline.Token);
        _status = response.StatusCode;
        _contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
        await using var stream = await response.Content.ReadAsStreamAsync(Deadline.Token);
        using var reader = new StreamReader(stream);
        _first = await reader.ReadLineAsync(Deadline.Token);
        (await reader.ReadLineAsync(Deadline.Token)).ShouldEqual(string.Empty);

        // The origin cannot send event two or finish until event one has crossed YARP.
        Harness.Arc.FirstEventRead.SetResult();
        _second = await reader.ReadLineAsync(Deadline.Token);
        (await reader.ReadLineAsync(Deadline.Token)).ShouldEqual(string.Empty);
        _forwarded = Assert.Single(Harness.Arc.Received);
    }

    [Fact] void should_accept_the_stream() => _status.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_preserve_the_content_type() => _contentType.ShouldEqual("text/event-stream");
    [Fact] void should_deliver_the_first_event_without_buffering_the_response() => _first.ShouldEqual("data: first");
    [Fact] void should_deliver_another_event_on_the_same_stream() => _second.ShouldEqual("data: second");
    [Fact] void should_forward_the_sse_path() => _forwarded.Path.ShouldEqual("/.cratis/queries/sse");
}
