// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_the_upstream_sets_a_policy : given.an_auth_proxy
{
    async Task Because() => _response = await _client.GetAsync("/portal/upstream-policy");

    [Fact] void should_preserve_the_response_status() => _response.StatusCode.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_use_the_expected_policy() => _response.Headers.GetValues("X-Robots-Tag").ShouldContainOnly("noarchive");
}
