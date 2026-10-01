// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_declared_port_differs_from_the_requested_one : Specification
{
    bool _onDeclaredPort;
    bool _onDefaultPort;
    bool _onDefaultHttpsPortWhenDeclared;

    void Because()
    {
        var declared = new HostString("billing.example.com:8443");
        var declaredDefault = new HostString("billing.example.com:443");

        var request = new DefaultHttpContext().Request;
        request.Scheme = "https";
        request.Host = new HostString("billing.example.com:8443");
        _onDeclaredPort = ServiceRoutes.Matches(declared, request);

        request.Host = new HostString("billing.example.com");
        _onDefaultPort = ServiceRoutes.Matches(declared, request);
        _onDefaultHttpsPortWhenDeclared = ServiceRoutes.Matches(declaredDefault, request);
    }

    [Fact] void should_match_the_declared_port() => _onDeclaredPort.ShouldBeTrue();
    [Fact] void should_not_match_another_port() => _onDefaultPort.ShouldBeFalse();
    [Fact] void should_treat_a_request_without_a_port_as_on_its_scheme_default() => _onDefaultHttpsPortWhenDeclared.ShouldBeTrue();
}
