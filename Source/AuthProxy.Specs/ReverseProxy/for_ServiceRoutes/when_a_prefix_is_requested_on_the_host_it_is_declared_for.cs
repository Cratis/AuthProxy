// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_prefix_is_requested_on_the_host_it_is_declared_for : given.services_routed_by_host_and_path
{
    void Establish() => Request("tenant.example.com", "/reports/api/orders");

    void Because() => Resolve();

    [Fact] void should_prefer_the_host_specific_prefix() => _result!.Name.ShouldEqual("tenant-reports");
}
