// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathConfigurationValidator;

public class when_nothing_is_declared : Specification
{
    [Fact] void should_accept_the_configuration() => new ForwardingPathConfigurationValidator().Validate(null, new C.AuthProxy()).Succeeded.ShouldBeTrue();
}
