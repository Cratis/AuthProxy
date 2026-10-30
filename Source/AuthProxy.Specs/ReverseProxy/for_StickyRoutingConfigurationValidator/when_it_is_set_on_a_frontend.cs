// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator;

public class when_it_is_set_on_a_frontend : given.a_validator
{
    void Because() => _result = Validate(new()
    {
        Services = new Dictionary<string, C.Service>() { ["core"] = new() { Frontend = new() { BaseUrl = "http://core/", StickyRouting = Sticky() } } },
    });

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_full_key() => _result.FailureMessage.ShouldContain("Cratis:AuthProxy:Services:core:Frontend:StickyRouting");
}
