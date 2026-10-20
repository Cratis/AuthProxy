// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_exclusion_is_off : given.an_auth_proxy
{
    protected override bool Exclude => false;

    async Task Because() => _response = await _client.GetAsync("/robots.txt");

    [Fact] void should_still_require_authentication() => _response.StatusCode.ShouldEqual(HttpStatusCode.Unauthorized);
    [Fact] void should_not_add_a_robots_header() => _response.Headers.Contains("X-Robots-Tag").ShouldBeFalse();
}
