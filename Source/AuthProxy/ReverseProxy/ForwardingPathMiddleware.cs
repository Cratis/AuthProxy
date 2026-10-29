// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>Enforces forwarding rules after YARP has selected the authoritative route.</summary>
/// <param name="next">The remaining proxy pipeline.</param>
/// <param name="options">The current service configuration.</param>
/// <param name="logger">The privacy-safe denial logger.</param>
public class ForwardingPathMiddleware(RequestDelegate next, IOptionsMonitor<C.AuthProxy> options, ILogger<ForwardingPathMiddleware> logger)
{
    /// <summary>Invokes the selected service's forwarding gate.</summary>
    /// <param name="context">The request context.</param>
    /// <returns>The asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        var config = options.CurrentValue;
        if (!ForwardingPathPolicy.AnyConfigured(config))
        {
            await next(context);
            return;
        }
        var service = ServiceRoutes.Resolve(context.Request, config);
        var refusal = service is null ? ForwardingPathRefusal.UnresolvedService : Evaluate(context, service.Service);
        if (refusal == ForwardingPathRefusal.None)
        {
            await next(context);
            return;
        }
        logger.Refused(context.Request.Method, RequestPathRedaction.Redact(context.Request.Path), service?.Name ?? "unknown", refusal);
        await UniformDenial.Write(context);
    }

    static ForwardingPathRefusal Evaluate(HttpContext context, C.Service service)
    {
        var metadata = context.GetReverseProxyFeature().Route.Config.Metadata;
        var prefix = metadata?.GetValueOrDefault(ServiceRoutes.StripPathPrefixMetadataKey);
        var path = ForwardingPathPolicy.EffectivePath(context.Request.Path, prefix);
        return ForwardingPathPolicy.Evaluate(context.Request, service, path);
    }
}
