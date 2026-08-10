// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementListenerIsolation;

/// <summary>
/// The public listener carries on serving everything it served before, and answers the management paths to
/// nobody.
/// <para>
/// Both halves matter. A management path reaching the public listener would publish a surface that is
/// private by design to the entire internet; anything else being refused there would be an outage caused by
/// switching on a health endpoint.
/// </para>
/// </summary>
public class when_a_request_arrives_on_the_public_port : given.an_isolated_management_listener
{
    [Fact] void should_refuse_the_liveness_path() => Decide(PublicPort, LivePath).ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_refuse_the_readiness_path() => Decide(PublicPort, ReadyPath).ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_serve_the_root_as_before() => Decide(PublicPort, "/").ShouldEqual(ManagementDisposition.Continue);
    [Fact] void should_serve_an_api_path_as_before() => Decide(PublicPort, "/api/x").ShouldEqual(ManagementDisposition.Continue);
    [Fact] void should_serve_the_providers_endpoint_as_before() => Decide(PublicPort, WellKnownPaths.Providers).ShouldEqual(ManagementDisposition.Continue);
    [Fact] void should_serve_a_declared_anonymous_prefix_as_before() => Decide(PublicPort, "/public").ShouldEqual(ManagementDisposition.Continue);
    [Fact] void should_serve_a_sibling_of_a_management_path_as_before() => Decide(PublicPort, "/health").ShouldEqual(ManagementDisposition.Continue);
    [Fact] void should_serve_a_path_below_a_management_path_as_before() => Decide(PublicPort, "/health/status").ShouldEqual(ManagementDisposition.Continue);
}
