// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_prefix_and_a_service_header_disagree : given.services_routed_by_host_and_path
{
    void Establish()
    {
        Request("www.example.com", "/reports/api/orders");
        _context.Request.Headers[Headers.ServiceId] = "portal";
    }

    void Because() => Resolve();

    [Fact] void should_let_the_prefix_claim_its_path() => _result!.Name.ShouldEqual("reports");
}
