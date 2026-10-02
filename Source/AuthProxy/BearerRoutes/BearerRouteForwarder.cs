// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms.Builder;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Forwards bearer-route requests straight to the service backend.
/// </summary>
/// <remarks>
/// A bearer route does not go through the reverse-proxy route table, because everything that table's routes are
/// guarded by — the cookie session, provider selection, tenant selection, identity verification — is exactly what
/// a bearer route must not use. It forwards with the same default transforms (<c language="text">X-Forwarded-*</c>, header
/// copying), the same HTTP client configuration and the same timeouts as the table's routes, then replaces every identity header with what
/// <see cref="BearerForwardedIdentity"/> vouches for.
/// </remarks>
/// <param name="forwarder">The YARP forwarder.</param>
/// <param name="clientFactory">The YARP client factory, which applies the reverse proxy's own client configuration.</param>
/// <param name="transformBuilder">The YARP transform builder.</param>
/// <param name="config">The current configuration, including the backend's activity timeout.</param>
/// <param name="logger">The logger.</param>
public sealed class BearerRouteForwarder(
    IHttpForwarder forwarder,
    IForwarderHttpClientFactory clientFactory,
    ITransformBuilder transformBuilder,
    IOptionsMonitor<C.AuthProxy> config,
    ILogger<BearerRouteForwarder> logger) : IBearerRouteForwarder, IDisposable
{
    readonly HttpTransformer _transformer = transformBuilder.Create(context => context.RequestTransforms.Add(new BearerRouteHeadersTransform()));

    readonly HttpMessageInvoker _invoker = clientFactory.CreateClient(new ForwarderHttpClientContext
    {
        ClusterId = "bearer-routes",
        OldConfig = HttpClientConfig.Empty,
        OldMetadata = null,
        OldClient = null,
        NewConfig = HttpClientConfig.Empty,
        NewMetadata = null,
    });

    /// <inheritdoc/>
    public async Task Forward(HttpContext context, ResolvedBearerRoute route, BearerForwardedIdentity? identity)
    {
        if (identity is null)
        {
            context.Items.Remove(BearerRouteDefaults.ForwardedIdentityItemKey);
        }
        else
        {
            context.Items[BearerRouteDefaults.ForwardedIdentityItemKey] = identity;
        }

        var current = config.CurrentValue;
        current.Services.TryGetValue(route.ServiceName, out var service);
        var requestConfig = new ForwarderRequestConfig
        {
            ActivityTimeout = service?.Backend?.ActivityTimeout
                ?? service?.ActivityTimeout
                ?? current.ActivityTimeout
                ?? C.AuthProxy.DefaultActivityTimeout,
        };
        var error = await forwarder.SendAsync(context, route.BackendBaseUrl, _invoker, requestConfig, _transformer);
        if (error != ForwarderError.None)
        {
            logger.BearerRouteForwardingFailed(
                context.Features.Get<IForwarderErrorFeature>()?.Exception,
                route.Prefix,
                route.ServiceName,
                error);
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _invoker.Dispose();
}
