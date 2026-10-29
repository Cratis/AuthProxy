// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_nothing_is_declared : given.a_policy
{
    [Fact] void should_forward_even_a_noncanonical_path() => Evaluate("/a%2fb", header: "X-HTTP-Method-Override").ShouldEqual(ForwardingPathRefusal.None);
    [Fact] void should_not_report_a_policy() => ForwardingPathPolicy.IsConfigured(_service).ShouldBeFalse();
    [Fact] void should_not_report_any_policy() => ForwardingPathPolicy.AnyConfigured(new C.AuthProxy()).ShouldBeFalse();
}
