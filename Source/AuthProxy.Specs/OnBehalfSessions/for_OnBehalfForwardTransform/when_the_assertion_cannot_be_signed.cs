// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfForwardTransform;

/// <summary>
/// A represented identity is never forwarded without the assertion that says who is acting. The transform throws, and
/// YARP fails the request without contacting the backend.
/// </summary>
public class when_the_assertion_cannot_be_signed : Specification
{
    RequestTransformContext _transformContext;
    Exception _error;

    void Establish()
    {
        var attestations = Substitute.For<IOnBehalfAttestations>();
        attestations.TryIssueForForward(default!, default!, default!, default!, out _).ReturnsForAnyArgs(false);
        var httpContext = new DefaultHttpContext { User = Sessions.ActorPrincipal() };
        httpContext.Request.Method = HttpMethods.Get;
        httpContext.SetOnBehalf(new OnBehalfContext(Sessions.At(DateTimeOffset.UtcNow), Sessions.Represented(), "actor", attestations));
        var route = new RouteConfig
        {
            RouteId = "portal-route",
            ClusterId = "portal-backend-cluster",
            Metadata = new Dictionary<string, string> { [ServiceSelection.RouteMetadataKey] = OnBehalfConfiguration.ServiceName },
        };
        httpContext.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(new RouteModel(route, new ClusterState(route.ClusterId), HttpTransformer.Default)), "proxied"));
        _transformContext = new RequestTransformContext
        {
            HttpContext = httpContext,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, (Uri?)null),
            Path = "/orders",
        };
        _transformContext.ProxyRequest.SetMicrosoftIdentityHeaders(Sessions.Represented());
    }

    async Task Because() => _error = await Catch.Exception(async () => await new OnBehalfForwardTransform().ApplyAsync(_transformContext));

    [Fact] void should_refuse_to_forward() => _error.ShouldBeOfExactType<OnBehalfAssertionCouldNotBeIssued>();
    [Fact] void should_not_forward_the_actor() => _transformContext.ProxyRequest.Headers.Contains(Headers.OnBehalfActor).ShouldBeFalse();
}
