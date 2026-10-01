// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_the_query_parameter_names_a_service : given.services_routed_by_host_and_path
{
    void Establish()
    {
        Request("www.example.com", "/api/customers");
        _context.Request.QueryString = new QueryString("?service=portal");
    }

    void Because() => Resolve();

    [Fact] void should_route_to_the_named_service() => _result!.Name.ShouldEqual("portal");
}
