// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

public class when_routed_service_has_mixed_casing : Specification
{
    List<RouteConfig> _routes;
    List<RequestTransformContext> _contexts;

    void Establish()
    {
        _routes = [];
        _contexts = [];
        foreach (var hasFrontend in new[] { true, false })
        {
            var config = new C.AuthProxy
            {
                Services = new Dictionary<string, C.Service>
                {
                    ["Studio"] = new()
                    {
                        Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/" },
                        Frontend = hasFrontend ? new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" } : null,
                        AnonymousPaths = ["/api/public", "/public"],
                    },
                },
            };
            var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
            monitor.CurrentValue.Returns(config);
            using var provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
            _routes.AddRange(provider.GetConfig().Routes);
        }

        foreach (var config in _routes)
        {
            var context = new RequestTransformContext
            {
                HttpContext = new DefaultHttpContext(),
                ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://backend.local/api/test"),
            };
            context.HttpContext.Request.Headers[Headers.ServiceId] = "studio";
            context.HttpContext.Request.Headers[Headers.LegacyServiceId] = "STUDIO";
            context.ProxyRequest.Headers.Add(Headers.ServiceId, "studio");
            context.ProxyRequest.Headers.Add(Headers.LegacyServiceId, "STUDIO");
            var route = new RouteModel(config, new ClusterState(config.ClusterId!), HttpTransformer.Default);
            context.HttpContext.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(route), "proxied"));
            _contexts.Add(context);
        }
    }

    async Task Because()
    {
        var transform = new InjectIdentityHeadersTransform();
        foreach (var context in _contexts)
        {
            await transform.ApplyAsync(context);
        }
    }

    [Fact] void should_preserve_the_configured_name_in_every_route() => _routes.Select(_ => _.Metadata![ServiceSelection.RouteMetadataKey]).Distinct().ShouldContainOnly("Studio");
    [Fact] void should_keep_route_ids_lowercase() => _routes.TrueForAll(_ => !_.RouteId.Any(char.IsUpper)).ShouldBeTrue();
    [Fact] void should_keep_cluster_ids_lowercase() => _routes.TrueForAll(_ => !_.ClusterId!.Any(char.IsUpper)).ShouldBeTrue();
    [Fact] void should_forward_the_configured_name_under_the_current_header() => _contexts.Select(_ => _.ProxyRequest.Headers.GetValues(Headers.ServiceId).Single()).Distinct().ShouldContainOnly("Studio");
    [Fact] void should_forward_the_configured_name_under_the_legacy_header() => _contexts.Select(_ => _.ProxyRequest.Headers.GetValues(Headers.LegacyServiceId).Single()).Distinct().ShouldContainOnly("Studio");
}
