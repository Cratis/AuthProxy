// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_a_request_matches_no_route_and_a_service_is_the_default : Specification
{
    RoutedService? _result;

    void Because()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["direct"] = new() { Default = true, Backend = new C.ServiceEndpoint { BaseUrl = "http://direct/" } },
                ["runners"] = new() { PathPrefix = "/direct.runners.Runner", Backend = new C.ServiceEndpoint { BaseUrl = "http://direct:8082/" } },
            },
        };
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("cratis.direct");
        context.Request.Path = "/settings/runners";
        _result = ServiceRoutes.Resolve(context.Request, config);
    }

    [Fact] void should_resolve_the_default_service() => _result!.Name.ShouldEqual("direct");
}
