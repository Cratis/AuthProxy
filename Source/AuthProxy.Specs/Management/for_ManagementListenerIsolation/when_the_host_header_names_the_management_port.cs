// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementListenerIsolation;

/// <summary>
/// The <c>Host</c> header decides nothing, in either direction.
/// <para>
/// ASP.NET's own way of scoping endpoints to a port is <c>RequireHost("*:9110")</c>, and it matches that
/// header — which is a string the caller typed. Written into a request on the public listener it would make
/// the private endpoints answer the internet; written into an ordinary request it would make the proxy
/// refuse a legitimate caller who happens to sit behind an ingress that rewrites <c>Host</c>. Gating on the
/// socket the request was accepted on is the only thing here a caller cannot reach.
/// </para>
/// </summary>
public class when_the_host_header_names_the_management_port : given.an_isolated_management_listener
{
    [Fact] void should_still_refuse_liveness_on_the_public_listener() => Decide(PublicPort, LivePath, $"proxy.example.com:{ManagementPort}").ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_still_refuse_readiness_on_the_public_listener() => Decide(PublicPort, ReadyPath, $"proxy.example.com:{ManagementPort}").ShouldEqual(ManagementDisposition.Refuse);
    [Fact] void should_not_restrict_an_ordinary_request_on_the_public_listener() => Decide(PublicPort, "/api/x", $"proxy.example.com:{ManagementPort}").ShouldEqual(ManagementDisposition.Continue);
    [Fact] void should_not_restrict_the_root_on_the_public_listener() => Decide(PublicPort, "/", $"proxy.example.com:{ManagementPort}").ShouldEqual(ManagementDisposition.Continue);
}
