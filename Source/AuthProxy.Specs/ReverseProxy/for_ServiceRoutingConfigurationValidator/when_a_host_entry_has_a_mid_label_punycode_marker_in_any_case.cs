// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_a_host_entry_has_a_mid_label_punycode_marker_in_any_case
{
    [Fact] void should_refuse_the_lower_case_spelling() => ServiceRoutes.TryParseHost("ab--xn--c.example", out _).ShouldBeFalse();
    [Fact] void should_refuse_the_upper_case_spelling() => ServiceRoutes.TryParseHost("AB--XN--C.example", out _).ShouldBeFalse();
}
