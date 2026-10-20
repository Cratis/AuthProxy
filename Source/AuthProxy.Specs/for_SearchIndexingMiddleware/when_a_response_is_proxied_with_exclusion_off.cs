// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_a_response_is_proxied_with_exclusion_off : given.an_auth_proxy
{
    protected override bool Exclude => false;

    async Task Because() => _response = await _client.GetAsync("/portal");

    [Fact] void should_preserve_the_upstream_status() => _response.StatusCode.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_not_add_a_robots_header() => _response.Headers.Contains("X-Robots-Tag").ShouldBeFalse();
}
