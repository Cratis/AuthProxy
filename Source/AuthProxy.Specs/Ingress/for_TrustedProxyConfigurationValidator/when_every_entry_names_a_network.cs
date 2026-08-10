// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyConfigurationValidator;

public class when_every_entry_names_a_network : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new AuthProxy.Ingress.TrustedProxyConfigurationValidator().Validate(
        null,
        new C.Ingress { TrustedProxies = ["10.0.0.0/8", "2001:db8::/32", "203.0.113.7"] });

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
