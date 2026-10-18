// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// A YARP <see cref="RequestTransform"/> that attaches a fresh signed forwarding assertion to a proxied request.
/// </summary>
/// <param name="signer">The signer.</param>
/// <remarks>
/// Registered after every transform that writes an identity or tenant header or rewrites the path, so what is signed
/// is the request exactly as it leaves. An inbound assertion is always removed, whether signing is configured or not.
/// When signing is configured and the request cannot be signed, this throws, so the request fails with
/// <c language="text">502</c> and is never forwarded unsigned.
/// </remarks>
public sealed class ForwardedIdentitySignatureTransform(IForwardedIdentitySigner signer) : RequestTransform
{
    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        context.ProxyRequest.Headers.Remove(Headers.ForwardedIdentity);
        if (!signer.IsEnabled)
        {
            return ValueTask.CompletedTask;
        }

        var service = ServiceOf(context.HttpContext);
        if (string.IsNullOrWhiteSpace(service))
        {
            throw new ForwardedIdentityCouldNotBeSigned("The request is not routed to a configured service, so it has no audience to be signed for.");
        }

        // YARP sets the address only after every transform has run. Set it here, exactly as YARP would, so the
        // signed path is the one the request is sent with.
        context.ProxyRequest.RequestUri ??= RequestUtilities.MakeDestinationAddress(
            context.DestinationPrefix,
            context.Path,
            context.Query.QueryString);

        if (signer.Sign(context.ProxyRequest, signer.AudienceFor(service)) != ForwardedIdentitySigningStatus.Attested)
        {
            throw new ForwardedIdentityCouldNotBeSigned("The forwarded identity could not be signed.");
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Gets the service a proxied request is forwarded to: the bearer route's service, or the reverse-proxy route's.
    /// </summary>
    /// <param name="context">The request being forwarded.</param>
    /// <returns>The configuration key of the service, or <see langword="null"/> when there is none.</returns>
    static string? ServiceOf(HttpContext context) =>
        context.Items.TryGetValue(BearerRouteDefaults.ServiceItemKey, out var bearerService) && bearerService is string service
            ? service
            : ServiceSelection.FromRoute(context);
}
