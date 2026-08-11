// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for the private management listener.
/// </summary>
/// <remarks>
/// AuthProxy answers nothing about itself on the listener it serves the internet from, so a deployment that
/// wants a health signal has had to point an HTTP probe at an application path or fall back to a TCP probe
/// — which proves only that a process accepted a socket, not that configuration bound or that the Data
/// Protection key ring initialized.
/// <para>
/// Setting this section opens a second listener, on its own address and port, carrying the liveness and
/// readiness endpoints and nothing else. Leaving it unset is the default: no second socket is opened, no
/// endpoint exists, and AuthProxy binds exactly what it binds today.
/// </para>
/// <para>
/// The listener is private by intent. It defaults to loopback so it is reachable from a sidecar or a
/// kubelet on the same network namespace and from nowhere else, and the paths it answers exist only on it —
/// they are never added to the anonymous-path policy, the middleware pipeline or the reverse-proxy route
/// table, so a service that already serves <c>/health</c> keeps serving it.
/// </para>
/// </remarks>
public class Management
{
    /// <summary>
    /// Gets or sets the address the management listener binds. Defaults to <c>127.0.0.1</c>, which keeps it
    /// reachable from within the pod or container and unreachable from the network.
    /// Widen it only when the probe genuinely runs elsewhere, and understand that doing so publishes the
    /// endpoints to everything that can route to the address.
    /// </summary>
    public string BindAddress { get; set; } = "127.0.0.1";

    /// <summary>
    /// Gets or sets the port the management listener binds. There is deliberately no default: a port is a
    /// deployment's own decision, and a value invented here would either collide with something or become a
    /// well-known address for a surface that is supposed to be private.
    /// Leaving it unset while the section is present is refused at startup.
    /// </summary>
    public int? Port { get; set; }

    /// <summary>
    /// Gets or sets the path answering liveness — whether the request loop is servicing requests at all.
    /// It consults nothing, so it stays <c>200</c> while storage, the identity provider and every backend
    /// are unreachable, which is what keeps an orchestrator from restarting a healthy process during an
    /// outage of something else.
    /// </summary>
    public string LivePath { get; set; } = "/health/live";

    /// <summary>
    /// Gets or sets the path answering readiness — whether this instance can serve traffic. It verifies
    /// local capability only: the Data Protection key ring, which is what encrypts the authentication
    /// cookie and the AuthProxy-issued bearer tokens. It calls no backend, no identity endpoint and no
    /// authority, so a deployment whose every dependency is down still becomes ready.
    /// </summary>
    public string ReadyPath { get; set; } = "/health/ready";
}
