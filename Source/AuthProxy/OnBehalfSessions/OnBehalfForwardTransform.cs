// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// A YARP <see cref="RequestTransform"/> that adds the actor and the signed assertion to every request an active
/// on-behalf session forwards.
/// </summary>
/// <remarks>
/// It runs after every other request transform, so the path it signs is the path the backend receives, after any
/// prefix stripping and below the destination's own base path. The assertion binds that path, the method, the
/// service and the exact principal and actor header values, so it cannot be replayed against another request or
/// another service. No credential of the actor's is forwarded. A request whose assertion cannot be issued is never
/// sent: the transform throws, and YARP answers <c language="text">502</c> without contacting the backend.
/// </remarks>
public class OnBehalfForwardTransform : RequestTransform
{
    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        if (!context.HttpContext.TryGetOnBehalf(out var onBehalf))
        {
            return ValueTask.CompletedTask;
        }

        var service = ServiceSelection.FromRoute(context.HttpContext)
            ?? throw new OnBehalfAssertionCouldNotBeIssued("the request is not routed to a service");

        if (!context.ProxyRequest.Headers.TryGetValues(Headers.Principal, out var principals) || principals.Count() != 1)
        {
            throw new OnBehalfAssertionCouldNotBeIssued("the request does not carry exactly one principal");
        }

        var forward = new OnBehalfForward(service, new HttpMethod(context.HttpContext.Request.Method), PathAsSent(context));
        if (!onBehalf.TryIssueAssertion(forward, principals.Single(), out var assertion))
        {
            throw new OnBehalfAssertionCouldNotBeIssued("it could not be signed");
        }

        context.ProxyRequest.Headers.Authorization = null;
        context.ProxyRequest.Headers.Remove(Headers.OnBehalfActor);
        context.ProxyRequest.Headers.Remove(Headers.OnBehalfAssertion);
        context.ProxyRequest.Headers.Add(Headers.OnBehalfActor, onBehalf.ActorHeader);
        context.ProxyRequest.Headers.Add(Headers.OnBehalfAssertion, assertion);
        return ValueTask.CompletedTask;
    }

    static string PathAsSent(RequestTransformContext context) =>
        string.IsNullOrEmpty(context.DestinationPrefix)
            ? (context.Path.HasValue ? context.Path.ToUriComponent() : "/")
            : RequestUtilities.MakeDestinationAddress(context.DestinationPrefix, context.Path, QueryString.Empty).AbsolutePath;
}
