// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementListenerIsolation;

/// <summary>
/// The management port answers its two paths and nothing else at all.
/// <para>
/// Everything else it is offered is the deployment's actual surface — the root, an API path, AuthProxy's
/// own provider endpoint, a path the deployment declared anonymous, a bundled asset, an unknown path — and
/// each of them is refused with the same not-found rather than handed onward. Whatever can reach this port
/// bypassed the ingress by definition; letting one of these through would make the private listener a way
/// around authentication rather than a health signal.
/// </para>
/// </summary>
public class when_a_request_arrives_on_the_management_port : given.an_isolated_management_listener
{
    [Fact] void should_answer_liveness() => Decide(ManagementPort, LivePath).ShouldEqual(ManagementDisposition.Live);
    [Fact] void should_answer_readiness() => Decide(ManagementPort, ReadyPath).ShouldEqual(ManagementDisposition.Ready);
    [Fact] void should_refuse_the_root() => Decide(ManagementPort, "/").ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_refuse_an_api_path() => Decide(ManagementPort, "/api/x").ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_refuse_the_providers_endpoint() => Decide(ManagementPort, WellKnownPaths.Providers).ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_refuse_a_declared_anonymous_prefix() => Decide(ManagementPort, "/public").ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_refuse_a_bundled_asset() => Decide(ManagementPort, "/index.html").ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_refuse_an_arbitrary_unknown_path() => Decide(ManagementPort, "/anything-at-all").ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_refuse_a_path_below_a_management_path() => Decide(ManagementPort, $"{LivePath}/deeper").ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_answer_liveness_whatever_the_host_header_says() => Decide(ManagementPort, LivePath, "attacker.example.com").ShouldEqual(ManagementDisposition.Live);
}
