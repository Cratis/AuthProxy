// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator;

public class when_the_base_url_host_is_an_ip_and_no_replica_host_is_stated : given.a_validator
{
    void Because() => _result = Validate(Backend(Sticky(replicaHost: string.Empty), baseUrl: "http://10.0.0.5:8080/"));

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_replica_host_key() => _result.FailureMessage.ShouldContain("Backend:StickyRouting:ReplicaHost");
}
