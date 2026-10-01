// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Removes a service's path prefix from the forwarded path and announces it in <c language="text">X-Forwarded-Prefix</c>,
/// for routes of a service that sets <see cref="Configuration.Service.StripPathPrefix"/>.
/// </summary>
/// <param name="prefix">The removed prefix.</param>
/// <remarks>
/// The announced prefix is the request's own path base followed by the removed prefix, so it stays correct when
/// AuthProxy itself is served below a prefix by a trusted proxy in front of it.
/// </remarks>
public sealed class PathPrefixTransform(string prefix) : RequestTransform
{
    /// <summary>
    /// The header that carries the removed prefix to the service.
    /// </summary>
    public const string ForwardedPrefixHeader = "X-Forwarded-Prefix";

    /// <summary>
    /// Adds the transforms a route needs when its metadata asks for the prefix to be stripped.
    /// </summary>
    /// <param name="context">The transform builder context of the route.</param>
    public static void Apply(TransformBuilderContext context)
    {
        if (context.Route.Metadata?.TryGetValue(ServiceRoutes.StripPathPrefixMetadataKey, out var prefix) != true
            || string.IsNullOrEmpty(prefix))
        {
            return;
        }

        context.AddPathRemovePrefix(prefix);

        // YARP appends its default X-Forwarded-* transforms after every custom one, and its prefix transform
        // would overwrite this one with the bare path base. Add the same defaults explicitly, ahead of this one.
        context.UseDefaultForwarders = false;
        context.AddXForwarded();
        context.RequestTransforms.Add(new PathPrefixTransform(prefix));
    }

    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        var forwardedPrefix = context.HttpContext.Request.PathBase.Add(new PathString(prefix));
        RemoveHeader(context, ForwardedPrefixHeader);
        AddHeader(context, ForwardedPrefixHeader, forwardedPrefix.ToUriComponent());

        return ValueTask.CompletedTask;
    }
}
