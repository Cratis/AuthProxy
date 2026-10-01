// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_host_is_requested_without_a_selection : given.services_routed_by_host_and_path
{
    void Establish() => Request("billing.example.com", "/invoices/42");

    void Because() => Resolve();

    [Fact] void should_route_to_the_service_declaring_the_host() => _result!.Name.ShouldEqual("billing");
}
