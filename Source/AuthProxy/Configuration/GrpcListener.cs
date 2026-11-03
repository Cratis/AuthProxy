// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Configures a listener that speaks HTTP/2 only, without TLS - what an ingress that terminates TLS uses to hand gRPC
/// calls to the proxy (ingress-nginx's <c language="text">backend-protocol: GRPC</c>, for instance).
/// </summary>
/// <remarks>
/// A plain-text listener that also accepts HTTP/1.1 cannot take gRPC: without TLS there is no protocol negotiation, so
/// an HTTP/2 client has to know in advance that the other end speaks nothing else. The listener runs the same pipeline
/// as the public one - authentication, tenancy, anonymous paths, forwarding - so a gRPC service behind the proxy is
/// declared like any other, with its backend's <see cref="ServiceEndpoint.Protocol"/> set to
/// <see cref="BackendProtocol.Http2"/>. Leave this section unset - the default - and no additional socket is opened.
/// </remarks>
public class GrpcListener
{
    /// <summary>
    /// Gets or sets the address the listener binds. Defaults to every address, since the ingress reaches it from outside
    /// the pod.
    /// </summary>
    public string BindAddress { get; set; } = "*";

    /// <summary>
    /// Gets or sets the port the listener binds. Required; there is no default, because a port is the deployment's own
    /// decision.
    /// </summary>
    public int? Port { get; set; }
}
