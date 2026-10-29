// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathConfigurationValidator;

public class when_the_root_is_declared : Specification
{
    [Fact] void should_accept_an_exact_root() => ForwardingPathPolicy.Evaluate(new C.ForwardingPathRule { Path = "/", Match = C.ForwardingPathMatch.Exact }, out _, out _).ShouldEqual(ForwardingPathEntryRejection.None);
    [Fact] void should_refuse_a_root_prefix() => ForwardingPathPolicy.Evaluate(new C.ForwardingPathRule { Path = "/" }, out _, out _).ShouldEqual(ForwardingPathEntryRejection.RootPrefix);
}
