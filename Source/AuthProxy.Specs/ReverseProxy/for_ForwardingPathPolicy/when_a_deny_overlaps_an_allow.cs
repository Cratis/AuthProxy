// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_a_deny_overlaps_an_allow : given.a_policy
{
    void Establish()
    {
        _service.ForwardedPaths = [new() { Path = "/api" }];
        _service.DeniedPaths = [new() { Path = "/api/private" }];
    }

    [Fact] void should_refuse_the_denied_path() => Evaluate("/api/private/x").ShouldEqual(ForwardingPathRefusal.Denied);
    [Fact] void should_allow_a_sibling() => Evaluate("/api/public").ShouldEqual(ForwardingPathRefusal.None);

    [Fact]
    void should_fail_closed_if_validation_was_bypassed()
    {
        var service = new C.Service { DeniedPaths = [new() { Path = "bad" }] };
        var request = new DefaultHttpContext().Request;
        request.Path = "/other";
        ForwardingPathPolicy.Evaluate(request, service, request.Path).ShouldEqual(ForwardingPathRefusal.NotAllowed);
    }

    [Fact]
    void should_resolve_a_replacement_service_without_the_old_cached_rules()
    {
        Evaluate("/api/private").ShouldEqual(ForwardingPathRefusal.Denied);
        var replacement = new C.Service { ForwardedPaths = [new() { Path = "/api/private" }] };
        var request = new DefaultHttpContext().Request;
        request.Path = "/api/private";
        request.Method = "GET";
        ForwardingPathPolicy.Evaluate(request, replacement, request.Path).ShouldEqual(ForwardingPathRefusal.None);
    }
}
