// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementListenerIsolation.given;

/// <summary>
/// A management listener on its own port, and the means to present it a request that arrived on a chosen
/// socket carrying a chosen <c>Host</c> header.
/// </summary>
/// <remarks>
/// The two are set independently on purpose. Which socket a request arrived on is a fact of the connection;
/// what the <c>Host</c> header says is whatever the caller wrote. Every question these specs ask is about
/// what happens when the two disagree.
/// </remarks>
public class an_isolated_management_listener : Specification
{
    protected const int ManagementPort = 9110;
    protected const int PublicPort = 8080;
    protected const string LivePath = "/health/live";
    protected const string ReadyPath = "/health/ready";

    protected ManagementListenerIsolation _isolation;

    void Establish() => _isolation = new ManagementListenerIsolation(ManagementPort, LivePath, ReadyPath);

    protected ManagementDisposition Decide(int localPort, string path, string? host = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.LocalPort = localPort;
        context.Request.Path = path;
        context.Request.Host = new HostString(host ?? $"proxy.example.com:{PublicPort}");

        return _isolation.Decide(context);
    }
}
