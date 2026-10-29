// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathConfigurationValidator;

public class when_a_method_is_not_a_token : Specification
{
    [Theory]
    [InlineData("")]
    [InlineData("GET POST")]
    [InlineData("GET\r\n")]
    [InlineData("GÉT")]
    [InlineData("GET/POST")]
    public void should_refuse_the_entry(string method) => ForwardingPathPolicy.Evaluate(new C.ForwardingPathRule { Path = "/api", Methods = [method] }, out _, out _).ShouldEqual(ForwardingPathEntryRejection.InvalidMethod);
}
