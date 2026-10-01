// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_header_names_a_service_that_cannot_serve_the_path : given.services_routed_by_host_and_path
{
    void Establish()
    {
        Request("billing.example.com", "/dashboard");
        _context.Request.Headers[Headers.ServiceId] = "portal";
    }

    void Because() => Resolve();

    [Fact] void should_fall_through_to_the_host_like_the_route_table() => _result!.Name.ShouldEqual("billing");
}
