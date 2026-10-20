// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_robots_is_requested_with_post : given.an_auth_proxy
{
    async Task Because() => _response = await _client.PostAsync("/robots.txt", new StringContent(""));

    [Fact] void should_still_require_authentication() => _response.StatusCode.ShouldEqual(HttpStatusCode.Unauthorized);
    [Fact] void should_still_request_no_indexing() => _response.Headers.GetValues("X-Robots-Tag").ShouldContainOnly("noindex, nofollow");
}
