// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Carries, for the length of a request, whether the caller AuthProxy actually accepted the connection from
/// was a trusted proxy.
/// </summary>
/// <remarks>
/// The answer has to be recorded before the forwarded-headers middleware runs, because that middleware
/// overwrites <see cref="ConnectionInfo.RemoteIpAddress"/> with what the header claimed. Afterwards there is
/// no longer any way to ask who actually connected, so anything downstream that needs to know whether the
/// request came through the deployment's own infrastructure — the geo headers a fronting CDN adds, for
/// instance — would otherwise have to guess.
/// </remarks>
public static class TrustedProxyPeer
{
    const string ItemKey = "Cratis.AuthProxy.Ingress.TrustedProxyPeer";

    /// <summary>
    /// Records whether the request arrived from a trusted proxy.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to record it on.</param>
    /// <param name="trusted">Whether the peer is trusted.</param>
    public static void MarkTrustedProxyPeer(this HttpContext context, bool trusted) =>
        context.Items[ItemKey] = trusted;

    /// <summary>
    /// Determines whether the request arrived from a trusted proxy.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> when the request came from a trusted proxy; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// An unmarked request is not trusted. Every request through the ingress pipeline is marked, so an
    /// unmarked one is a context nobody vouched for — a request that never passed the boundary check, or a
    /// context constructed outside the pipeline entirely — and the safe reading of both is the same.
    /// </remarks>
    public static bool IsFromTrustedProxy(this HttpContext context) =>
        context.Items.TryGetValue(ItemKey, out var trusted) && trusted is true;
}
