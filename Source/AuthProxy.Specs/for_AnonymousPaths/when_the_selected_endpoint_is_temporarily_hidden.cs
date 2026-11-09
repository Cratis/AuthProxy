// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.for_AnonymousPaths;

public class when_the_selected_endpoint_is_temporarily_hidden : Specification
{
    DefaultHttpContext _context;
    Endpoint _selected;
    bool _anonymous;
    bool _passthrough;

    void Establish()
    {
        var route = new RouteModel(
            new RouteConfig
            {
                RouteId = "passthrough",
                ClusterId = "app",
                AuthorizationPolicy = MicroserviceReverseProxyConfigProvider.AnonymousAuthorizationPolicy,
                Metadata = new Dictionary<string, string> { [AnonymousPaths.PassCallerAuthorizationMetadataKey] = bool.TrueString }
            },
            new ClusterState("app"),
            HttpTransformer.Default);
        _selected = new Endpoint(null, new EndpointMetadataCollection(route), "passthrough");
        _context = new DefaultHttpContext();
        _context.SetEndpoint(_selected);
    }

    void Because()
    {
        AnonymousPaths.CaptureRouteDisposition(_context);
        _context.SetEndpoint(null);
        _anonymous = AnonymousPaths.IsAnonymousRoute(_context);
        _passthrough = AnonymousPaths.PassesCallerAuthorization(_context);
        AnonymousPaths.RestoreSelectedEndpoint(_context);
    }

    [Fact] void should_keep_the_selected_anonymous_disposition() => _anonymous.ShouldBeTrue();
    [Fact] void should_keep_the_selected_passthrough_disposition() => _passthrough.ShouldBeTrue();
    [Fact] void should_restore_the_same_endpoint_without_routing_again() => _context.GetEndpoint().ShouldEqual(_selected);
}
