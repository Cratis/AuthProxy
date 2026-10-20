// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_requesting_robots : given.an_auth_proxy
{
    string _body;

    async Task Because()
    {
        _response = await _client.GetAsync("/robots.txt");
        _body = await _response.Content.ReadAsStringAsync();
    }

    [Fact] void should_answer_anonymously() => _response.StatusCode.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_disallow_all_crawling() => _body.ShouldEqual("User-agent: *\nDisallow: /\n");
    [Fact] void should_use_plain_utf8_text() => _response.Content.Headers.ContentType.ToString().ShouldEqual("text/plain; charset=utf-8");
    [Fact] void should_request_no_indexing() => _response.Headers.GetValues("X-Robots-Tag").ShouldContainOnly("noindex, nofollow");
}
