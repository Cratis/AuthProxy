// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_a_child_of_robots_is_requested : given.an_auth_proxy
{
    async Task Because() => _response = await _client.GetAsync("/robots.txt/private");

    [Fact] void should_still_require_authentication() => _response.StatusCode.ShouldEqual(HttpStatusCode.Unauthorized);
}
