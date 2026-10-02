// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging.Abstractions;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware.given;

/// <summary>
/// The middleware in front of a request that the route table has sent to the backend of a service declaring an
/// access token, from a caller signed in with the session cookie.
/// </summary>
public class a_forwarding_middleware : Specification
{
    protected IUserAccessTokens _tokens;
    protected C.ServiceAccessToken _accessToken;
    protected DefaultHttpContext _context;
    protected bool _forwarded;
    protected AccessTokenForwardingMiddleware _middleware;
    protected string _authorizationPolicy = "default";
    protected string _endpoint = ReverseProxy.MicroserviceReverseProxyConfigProvider.BackendEndpoint;
    protected string? _destinationBinding = "bound-destination";
    protected IReadOnlyList<DestinationState> _availableDestinations = [new("bound-destination")];
    protected IReadOnlyList<DestinationState> _allDestinations = [new("bound-destination")];

    void Establish()
    {
        _accessToken = new() { Scopes = ["api://reporting/access_as_user"] };
        _tokens = Substitute.For<IUserAccessTokens>();
        _tokens.GetFor("session-id", Arg.Any<C.ServiceAccessToken>(), Arg.Any<CancellationToken>()).Returns(UserAccessTokenResult.Success("user-access-token"));

        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user")], "Cookies"))
        };
        _context.Items[AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] = CookieAuthenticationDefaults.AuthenticationScheme;
        _context.Items[UserTokenSessions.HttpContextItemKey] = "session-id";
        _context.Request.Headers.Authorization = "Bearer something-the-browser-sent";

        _middleware = new(
            _ =>
            {
                _forwarded = true;
                return Task.CompletedTask;
            },
            NullLogger<AccessTokenForwardingMiddleware>.Instance);
    }

    protected Task Invoke()
    {
        var metadata = new Dictionary<string, string>
        {
            [ReverseProxy.MicroserviceReverseProxyConfigProvider.ServiceMetadataKey] = "reporting",
            [ReverseProxy.MicroserviceReverseProxyConfigProvider.EndpointMetadataKey] = _endpoint,
            [ReverseProxy.MicroserviceReverseProxyConfigProvider.AccessTokenMetadataKey] = JsonSerializer.Serialize(_accessToken),
        };
        if (_destinationBinding is not null)
        {
            metadata[ReverseProxy.MicroserviceReverseProxyConfigProvider.DestinationMetadataKey] = _destinationBinding;
        }

        var cluster = new ClusterModel(
            new ClusterConfig
            {
                ClusterId = "reporting-cluster",
                Metadata = metadata,
            },
            new HttpMessageInvoker(new SocketsHttpHandler()));
        var route = new RouteModel(new RouteConfig { RouteId = "route", AuthorizationPolicy = _authorizationPolicy }, null, HttpTransformer.Empty);
        var feature = Substitute.For<IReverseProxyFeature>();
        feature.Route.Returns(route);
        feature.Cluster.Returns(cluster);
        feature.AvailableDestinations.Returns(_availableDestinations);
        feature.AllDestinations.Returns(_allDestinations);
        _context.Features.Set(feature);

        return _middleware.InvokeAsync(_context, _tokens);
    }
}
