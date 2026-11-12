// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Specifications;

namespace Cratis.AuthProxy.Security.for_ArcCratisPaths;

[Collection(ArcCratisSpecCollection.Name)]
public class when_sse_unsubscribe_is_posted(ArcCratisHarness harness) : given.an_arc_proxy(harness)
{
    HttpStatusCode _status;
    string _body;
    ForwardedRequest _forwarded;

    async Task Because()
    {
        using var request = Request("/.cratis/queries/sse/unsubscribe");
        request.Method = HttpMethod.Post;
        request.Content = new StringContent("{\"connectionId\":\"c1\"}");
        using var response = await Client.SendAsync(request, Deadline.Token);
        _status = response.StatusCode;
        _body = await response.Content.ReadAsStringAsync(Deadline.Token);
        _forwarded = Assert.Single(Harness.Arc.Received);
    }

    [Fact] void should_preserve_the_backend_status() => _status.ShouldEqual(HttpStatusCode.Accepted);
    [Fact] void should_deliver_the_body_to_the_origin() => _body.ShouldEqual("unsubscribe:{\"connectionId\":\"c1\"}");
    [Fact] void should_forward_the_path() => _forwarded.Path.ShouldEqual("/.cratis/queries/sse/unsubscribe");
    [Fact] void should_preserve_the_method() => _forwarded.Method.ShouldEqual("POST");
}
