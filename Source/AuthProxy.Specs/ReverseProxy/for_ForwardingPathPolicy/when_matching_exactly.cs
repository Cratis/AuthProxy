// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_matching_exactly : given.a_policy
{
    void Establish() => _service.ForwardedPaths = [new() { Path = "/health", Match = C.ForwardingPathMatch.Exact }, new() { Path = "/", Match = C.ForwardingPathMatch.Exact }];

    [Theory]
    [InlineData("/health", true)]
    [InlineData("/HEALTH/", true)]
    [InlineData("/health/x", false)]
    [InlineData("/", true)]
    [InlineData("", true)]
    [InlineData("/x", false)]
    public void should_match_only_the_normalized_path(string path, bool allowed) => Evaluate(path).ShouldEqual(allowed ? ForwardingPathRefusal.None : ForwardingPathRefusal.NotAllowed);
}
