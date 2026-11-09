// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_authorization_passthrough_is_listed_on_an_anonymous_path : given.a_service_routing_validator
{
    void Establish()
    {
        _services["one"] = Routable();
        _services["one"].AnonymousPaths = ["/hooks"];
        _services["one"].PassCallerAuthorizationPaths = ["/Hooks"];
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
