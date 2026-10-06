// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_decomposed_unicode_host_is_declared : given.services_routed_by_host_and_path
{
    void Establish()
    {
        _config.Services["billing"].Hosts = ["bu\u0308cher.example:8443"];
        _context.Request.Host = HostString.FromUriComponent("xn--bcher-kva.example:8443");
        _context.Request.Path = "/invoices/42";
    }

    void Because() => Resolve();

    [Fact] void should_resolve_the_service() => _result!.Name.ShouldEqual("billing");
    [Fact] void should_normalize_the_declared_host_to_composed_unicode() => ServiceRoutes.HostsOf(_config.Services["billing"]).Single().Value.ShouldEqual("bücher.example:8443");
    [Fact] void should_overlap_with_the_composed_declaration() => ServiceRoutes.Overlap(ServiceRoutes.HostsOf(_config.Services["billing"]).Single(), new HostString("bücher.example:8443")).ShouldBeTrue();
}
