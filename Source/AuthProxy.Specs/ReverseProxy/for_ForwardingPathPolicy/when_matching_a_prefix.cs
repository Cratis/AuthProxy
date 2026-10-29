// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_matching_a_prefix : given.a_policy
{
    void Establish() => _service.ForwardedPaths = [new() { Path = "/api" }];

    [Theory]
    [InlineData("/api", true)]
    [InlineData("/api/", true)]
    [InlineData("/API/x", true)]
    [InlineData("/apix", false)]
    [InlineData("/ap", false)]
    public void should_match_only_at_segment_boundaries(string path, bool allowed) => Evaluate(path).ShouldEqual(allowed ? ForwardingPathRefusal.None : ForwardingPathRefusal.NotAllowed);
}
