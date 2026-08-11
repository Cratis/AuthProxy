// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Gives every request a socket peer, and records what the proxy normalized it to.
/// </summary>
/// <remarks>
/// <para>
/// The in-memory test server never opens a socket, so <c>Connection.RemoteIpAddress</c> is <see langword="null"/>
/// on every request it serves. That is fatal to a spec about a trusted-proxy boundary and fatal in the worst
/// possible way: a null address matches no known network, so the untrusted direction passes for entirely the
/// wrong reason and the trusted direction cannot be written at all. A whole suite would sit there green while
/// measuring nothing. Stamping an address the spec chooses is what makes the boundary a real question.
/// </para>
/// <para>
/// It has to run ahead of everything in the proxy's own pipeline, which is why it is a startup filter: a
/// filter's middleware is placed in front of the application's, so the address is on the connection before
/// the trusted-proxy check reads it and long before the forwarded-headers middleware overwrites it.
/// </para>
/// <para>
/// The observation is taken on the way back out, once every middleware has had its turn. The forwarded-headers
/// middleware mutates the request in place rather than wrapping it, so the values seen here are exactly the
/// ones every later decision in the proxy used.
/// </para>
/// <para>
/// A sign-in notification is fired from here, on request, for the one thing that cannot be reached otherwise:
/// the notification is raised deep inside a real identity-provider handshake, which no spec can perform
/// against a fake authority. Everything downstream of the trigger is the production path — the real resolver
/// reading the real normalized request, the real notifier composing the payload, and a real POST to the origin
/// — so the only thing standing in for reality is what causes it to happen.
/// </para>
/// </remarks>
/// <param name="observations">Where to record the normalized request.</param>
/// <param name="defaultPeer">The address to use for a request that does not name one.</param>
sealed class SimulatedPeerStartupFilter(RequestObservations observations, string defaultPeer) : IStartupFilter
{
    /// <inheritdoc/>
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
        app =>
        {
            app.Use(async (context, proceed) =>
            {
                var peer = context.Request.Headers[TrustedProxyHarness.PeerHeader].ToString();
                var notifySignIn = context.Request.Headers.ContainsKey(TrustedProxyHarness.NotifySignInHeader);

                context.Request.Headers.Remove(TrustedProxyHarness.PeerHeader);
                context.Request.Headers.Remove(TrustedProxyHarness.NotifySignInHeader);

                context.Connection.RemoteIpAddress = IPAddress.Parse(string.IsNullOrEmpty(peer) ? defaultPeer : peer);
                context.Connection.RemotePort = 51234;

                await proceed();

                observations.Last = new ObservedRequest(
                    context.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
                    context.Request.Scheme,
                    context.Request.Host.Value ?? string.Empty,
                    context.Request.PathBase.Value ?? string.Empty,
                    context.Request.Headers["X-Forwarded-For"].ToString());

                if (notifySignIn)
                {
                    await context.RequestServices
                        .GetRequiredService<ISignInNotifier>()
                        .Notify(context, SignedIn());
                }
            });

            next(app);
        };

    static ClaimsPrincipal SignedIn() => new(new ClaimsIdentity(
        [
            new Claim("sub", "trusted-proxy-spec-subject"),
            new Claim("iss", "https://login.example.test/one"),
        ],
        "TrustedProxySpec"));
}
