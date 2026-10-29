// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens;
using Microsoft.AspNetCore.Authentication.Cookies;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.ReverseProxy.for_CallerAuthorizationHeaderTransform.given;

/// <summary>
/// A request carrying the caller's own Authorization header, on its way to a service, run through the transform.
/// </summary>
public class a_proxied_request : Specification
{
    protected string? _scheme = CookieAuthenticationDefaults.AuthenticationScheme;
    protected bool _authenticated = true;
    protected bool _proxyWroteHeader;
    protected C.CallerAuthorizationHeaderForwarding _setting;
    protected RequestTransformContext _transformContext;

    protected bool HeaderForwarded => _transformContext.ProxyRequest.Headers.Authorization is not null;

    protected async Task Apply()
    {
        var http = new DefaultHttpContext();
        if (_authenticated)
        {
            http.User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity("test"));
        }

        if (_scheme is not null)
        {
            http.Items[Cratis.AuthProxy.Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] = _scheme;
        }

        if (_proxyWroteHeader)
        {
            http.Items[AccessTokenForwardingMiddleware.ForwardedItemKey] = true;
        }

        var clusterModel = new ClusterModel(
            new ClusterConfig
            {
                ClusterId = "cluster",
                Metadata = _setting == C.CallerAuthorizationHeaderForwarding.Default
                    ? new Dictionary<string, string>()
                    : new Dictionary<string, string> { [MicroserviceReverseProxyConfigProvider.CallerAuthorizationHeaderMetadataKey] = _setting.ToString() }
            },
            new HttpMessageInvoker(new HttpClientHandler()));
        var route = new RouteModel(new RouteConfig { RouteId = "route", ClusterId = "cluster" }, new ClusterState("cluster"), HttpTransformer.Default);
        http.Features.Set<IReverseProxyFeature>(new ReverseProxyFeature
        {
            Route = route,
            Cluster = clusterModel,
            AllDestinations = [],
            AvailableDestinations = []
        });

        _transformContext = new RequestTransformContext
        {
            HttpContext = http,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, (Uri?)null),
            Path = "/orders"
        };
        _transformContext.ProxyRequest.Headers.Authorization = new("Bearer", "callers-own-token");

        await new CallerAuthorizationHeaderTransform().ApplyAsync(_transformContext);
    }
}
