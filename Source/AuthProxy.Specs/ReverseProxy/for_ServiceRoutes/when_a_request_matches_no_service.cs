// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_request_matches_no_service : given.services_routed_by_host_and_path
{
    void Establish() => Request("www.example.com", "/dashboard");

    void Because() => Resolve();

    [Fact] void should_resolve_no_service() => _result.ShouldBeNull();
}
