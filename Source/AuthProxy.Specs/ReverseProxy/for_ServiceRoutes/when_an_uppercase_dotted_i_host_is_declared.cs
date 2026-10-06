// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_an_uppercase_dotted_i_host_is_declared : given.services_routed_by_host_and_path
{
    void Establish()
    {
        _config.Services["billing"].Hosts = ["\u0130stanbul.example:8443"];
        _context.Request.Host = HostString.FromUriComponent("xn--istanbul-o0e.example:8443");
        _context.Request.Path = "/invoices/42";
    }

    void Because() => Resolve();

    [Fact] void should_resolve_the_service() => _result!.Name.ShouldEqual("billing");
    [Fact] void should_canonicalize_the_declared_host_and_preserve_the_port() => ServiceRoutes.HostsOf(_config.Services["billing"]).Single().Value.ShouldEqual("i\u0307stanbul.example:8443");
}
