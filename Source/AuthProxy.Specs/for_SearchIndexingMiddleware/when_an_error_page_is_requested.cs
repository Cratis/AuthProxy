// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_an_error_page_is_requested : given.an_auth_proxy
{
    async Task Because() => _response = await _client.GetAsync("/_pages/missing.html");

    [Fact] void should_preserve_the_response_status() => _response.StatusCode.ShouldEqual(HttpStatusCode.NotFound);
    [Fact] void should_use_the_expected_policy() => _response.Headers.GetValues("X-Robots-Tag").ShouldContainOnly("noindex, nofollow");
}
