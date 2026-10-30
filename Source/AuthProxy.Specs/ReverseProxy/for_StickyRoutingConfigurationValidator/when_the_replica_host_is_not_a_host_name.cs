// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator;

public class when_the_replica_host_is_not_a_host_name : given.a_validator
{
    static readonly string[] _hosts = ["10.0.0.1", "[fd00::1]", "host:80", "http://host", "host name", " host", "host/path"];
    List<ValidateOptionsResult> _results;

    void Because() => _results = [.. _hosts.Select(host => Validate(Backend(Sticky(host))))];

    [Fact] void should_fail_every_one() => _results.TrueForAll(_ => _.Failed).ShouldBeTrue();
    [Fact] void should_name_the_replica_host_key() => _results.TrueForAll(_ => _.FailureMessage.Contains("Backend:StickyRouting:ReplicaHost")).ShouldBeTrue();
}
