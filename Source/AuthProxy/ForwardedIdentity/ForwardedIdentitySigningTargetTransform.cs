// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Marks the actual routed destination without signing any pre-rewrite URI.</summary>
/// <param name="flow">The outbound proxy flow.</param>
internal sealed class ForwardedIdentitySigningTargetTransform(ForwardedIdentityFlow flow) : RequestTransform
{
    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        context.ProxyRequest.Options.Set(AnonymousPaths.ForwardWithoutIdentity, AnonymousPaths.IsAnonymousRoute(context.HttpContext));
        var service = flow == ForwardedIdentityFlow.BearerRoute
            ? context.HttpContext.Items[BearerRouteDefaults.ServiceItemKey] as string
            : ServiceSelection.FromRoute(context.HttpContext);
        if (service is not null)
        {
            context.ProxyRequest.Options.Set(ForwardedIdentitySigningTarget.OptionsKey, new(flow, service));
        }
        return ValueTask.CompletedTask;
    }
}
