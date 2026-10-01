// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_prefix_is_requested_on_another_host : given.services_routed_by_host_and_path
{
    void Establish() => Request("www.example.com", "/reports/dashboard");

    void Because() => Resolve();

    [Fact] void should_route_to_the_prefix_on_every_host() => _result!.Name.ShouldEqual("reports");
}
