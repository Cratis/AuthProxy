// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_authorization_passthrough_contradicts_a_strip_setting : given.a_service_routing_validator
{
    void Establish()
    {
        _services["one"] = Routable();
        _services["one"].AnonymousPaths = ["/hooks"];
        _services["one"].PassCallerAuthorizationPaths = ["/hooks"];
        _services["one"].CallerAuthorizationHeader = C.CallerAuthorizationHeaderForwarding.Strip;
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
}
