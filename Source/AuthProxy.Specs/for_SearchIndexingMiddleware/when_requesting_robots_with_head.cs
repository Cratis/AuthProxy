// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_requesting_robots_with_head : given.an_auth_proxy
{
    string _body;

    async Task Because()
    {
        _response = await _client.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/robots.txt"));
        _body = await _response.Content.ReadAsStringAsync();
    }

    [Fact] void should_answer_anonymously() => _response.StatusCode.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_not_write_a_body() => _body.ShouldBeEmpty();
    [Fact] void should_describe_the_get_body_length() => _response.Content.Headers.ContentLength.ShouldEqual(26);
    [Fact] void should_use_plain_utf8_text() => _response.Content.Headers.ContentType.ToString().ShouldEqual("text/plain; charset=utf-8");
    [Fact] void should_request_no_indexing() => _response.Headers.GetValues("X-Robots-Tag").ShouldContainOnly("noindex, nofollow");
}
