// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_authorization_passthrough_is_listed_on_an_authenticated_path : given.a_service_routing_validator
{
    void Establish()
    {
        _services["one"] = Routable();
        _services["one"].AnonymousPaths = ["/hooks"];
        _services["one"].PassCallerAuthorizationPaths = ["/private", "/hooks/deeper", "/hooksx", "/", "/%2e"];
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_refuse_every_entry() => _result.Failures!.Count().ShouldEqual(5);
}
