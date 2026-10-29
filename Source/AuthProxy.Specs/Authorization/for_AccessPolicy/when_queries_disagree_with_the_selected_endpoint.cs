// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

public class when_queries_disagree_with_the_selected_endpoint : given.a_selected_proxy_route
{
    [Theory]
    [InlineData("key-backend-cluster")]
    [InlineData("key-frontend-cluster")]
    public void should_keep_the_selected_endpoint_authoritative_for_routing_and_authorization(string cluster)
    {
        _config.Services["portal"] = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "http://portal.test/" },
            Frontend = new C.ServiceEndpoint { BaseUrl = "http://portal.test/" }
        };
        SelectCluster(cluster);
        _context.Request.Headers[Headers.ServiceId] = "portal";
        _context.Request.QueryString = new QueryString("?x-cratis-microservice=portal&service=portal");
        ServiceRoutes.Resolve(_context.Request, _config).Name.ShouldEqual("\u212Aey");
        _policy.Evaluate(_context, _config).IsGranted.ShouldBeFalse();
    }
}
