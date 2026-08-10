// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management;

/// <summary>
/// Decides, for one request, whether it belongs to the management listener.
/// </summary>
/// <param name="port">The port the management listener binds.</param>
/// <param name="livePath">The path answering liveness.</param>
/// <param name="readyPath">The path answering readiness.</param>
/// <remarks>
/// Isolation is gated on <see cref="ConnectionInfo.LocalPort"/> — the socket Kestrel accepted the request
/// on — and deliberately not on the <c>Host</c> header. ASP.NET's own port-scoping convention,
/// <c>RequireHost("*:9110")</c>, matches that header, and a header is whatever the caller wrote: a request
/// arriving on the public listener carrying <c>Host: anything:9110</c> would be treated as a management
/// request and answered from a surface that is supposed to be unreachable from the network. The accepted
/// socket cannot be forged by a caller, which is the entire point.
/// <para>
/// It gates in both directions. The management paths answer only on the management port, so probing the
/// public listener for them gets the same not-found as any other unknown path; and the management port
/// answers only those paths, so nothing that arrives on it — not <c>/</c>, not a declared anonymous path,
/// not a bundled asset — is ever handed to the middleware pipeline or the reverse proxy.
/// </para>
/// </remarks>
public sealed class ManagementListenerIsolation(int port, string livePath, string readyPath)
{
    readonly PathString _live = new(livePath);
    readonly PathString _ready = new(readyPath);

    /// <summary>
    /// Decides what to do with a request.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> of the request.</param>
    /// <returns>The <see cref="ManagementDisposition"/> to apply.</returns>
    public ManagementDisposition Decide(HttpContext context)
    {
        var onManagementListener = context.Connection.LocalPort == port;
        var path = context.Request.Path;

        if (path.Equals(_live, StringComparison.OrdinalIgnoreCase))
        {
            return onManagementListener ? ManagementDisposition.Live : ManagementDisposition.Refuse;
        }

        if (path.Equals(_ready, StringComparison.OrdinalIgnoreCase))
        {
            return onManagementListener ? ManagementDisposition.Ready : ManagementDisposition.Refuse;
        }

        return onManagementListener ? ManagementDisposition.Refuse : ManagementDisposition.Continue;
    }
}
