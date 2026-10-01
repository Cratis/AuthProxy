// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_host_is_requested_with_another_case_and_a_port : given.services_routed_by_host_and_path
{
    void Establish() => Request("Billing.Example.com:8443", "/invoices/42");

    void Because() => Resolve();

    [Fact] void should_match_the_host_case_insensitively_on_any_port() => _result!.Name.ShouldEqual("billing");
}
