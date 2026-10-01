// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_path_only_starts_with_the_prefix_characters : given.services_routed_by_host_and_path
{
    void Establish() => Request("www.example.com", "/reportsx/dashboard");

    void Because() => Resolve();

    [Fact] void should_not_treat_it_as_under_the_prefix() => _result.ShouldBeNull();
}
