// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

public class when_the_route_selects_session_context_forwarding : for_ClientPrincipalExtensions.given.a_recorded_session
{
    [Theory]
    [InlineData("enabled", true)]
    [InlineData("disabled", false)]
    [InlineData("unknown", false)]
    [InlineData(null, false)]
    public async Task should_use_only_the_routed_service(string? service, bool expected)
    {
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["enabled"] = new() { ForwardSessionContext = true }, ["disabled"] = new() } };
        await using var services = new ServiceCollection().Configure<C.AuthProxy>(options => options.Services = config.Services).BuildServiceProvider();
        _context.RequestServices = services;
        _context.Request.Host = new HostString(expected ? "disabled" : "enabled");
        _context.Request.Headers[Headers.ServiceId] = expected ? "disabled" : "enabled";
        _context.Request.QueryString = new QueryString("?service=enabled");
        if (service is not null)
        {
            var route = new RouteModel(new RouteConfig { RouteId = "routed", Metadata = new Dictionary<string, string> { [ServiceSelection.RouteMetadataKey] = service }, Match = new RouteMatch { Path = "/{**catch-all}" } }, new ClusterState("cluster"), HttpTransformer.Default);
            _context.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(route), "proxied"));
        }
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.example.test/request");
        await new InjectIdentityHeadersTransform().ApplyAsync(new RequestTransformContext { HttpContext = _context, ProxyRequest = request });
        ClientPrincipal.TryFromBase64(request.Headers.GetValues(Headers.Principal).Single(), out var principal).ShouldBeTrue();
        principal!.Claims.Any(_ => _.Type == SessionClaims.Started).ShouldEqual(expected);
        principal.Claims.Any(_ => _.Type == SessionClaims.SignInProvider).ShouldEqual(expected);
    }
}
