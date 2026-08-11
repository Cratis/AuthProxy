// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyConfigurationValidator;

public class when_an_entry_names_no_network : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new AuthProxy.Ingress.TrustedProxyConfigurationValidator().Validate(
        null,
        new C.Ingress { TrustedProxies = ["10.0.0.0/8", "not-an-address", "203.0.113.7"] });

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_fail_once_per_offending_entry() => _result.Failures.Count().ShouldEqual(1);
    [Fact] void should_name_the_offending_value() => _result.FailureMessage!.ShouldContain("not-an-address");
    [Fact] void should_name_the_offending_position() => _result.FailureMessage!.ShouldContain($"{C.Ingress.SectionKey}:TrustedProxies:1");
}
