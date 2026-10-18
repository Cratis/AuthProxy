// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform.given;

public class a_signature_transform : Specification
{
    protected IForwardedIdentitySigner _signer;
    protected ForwardedIdentitySignatureTransform _transform;
    protected RequestTransformContext _context;

    void Establish()
    {
        _signer = Substitute.For<IForwardedIdentitySigner>();
        _signer.AudienceFor(Arg.Any<string>()).Returns(call => $"{call.Arg<string>()}-audience");
        _transform = new ForwardedIdentitySignatureTransform(_signer);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = "/reports/api/items";
        httpContext.Request.QueryString = new QueryString("?page=2");
        _context = new RequestTransformContext
        {
            HttpContext = httpContext,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, (Uri?)null),
            DestinationPrefix = "https://reports.internal/base",
            Path = "/api/items",
            Query = new QueryTransformContext(httpContext.Request),
        };
        _context.ProxyRequest.Headers.TryAddWithoutValidation(Headers.ForwardedIdentity, "forged");
    }

    protected static void RouteTo(HttpContext context, string service)
    {
        var route = new RouteModel(
            new RouteConfig
            {
                RouteId = $"{service}-route",
                ClusterId = $"{service}-cluster",
                Metadata = new Dictionary<string, string> { [ServiceSelection.RouteMetadataKey] = service },
                Match = new RouteMatch { Path = "/{**catch-all}" },
            },
            new ClusterState($"{service}-cluster"),
            HttpTransformer.Default);
        context.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(route), "proxied"));
    }
}
