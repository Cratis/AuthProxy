// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_an_ascii_host_with_double_hyphens_is_declared : given.services_routed_by_host_and_path
{
    void Establish()
    {
        _config.Services["billing"].Hosts = ["My--Svc.default.svc.cluster.local:8080"];
        _context.Request.Host = HostString.FromUriComponent("my--svc.default.svc.cluster.local:8080");
        _context.Request.Path = "/invoices/42";
    }

    void Because() => Resolve();

    [Fact] void should_resolve_the_service() => _result!.Name.ShouldEqual("billing");
    [Fact] void should_keep_the_ascii_host_and_port() => ServiceRoutes.HostsOf(_config.Services["billing"]).Single().Value.ShouldEqual("my--svc.default.svc.cluster.local:8080");
}
