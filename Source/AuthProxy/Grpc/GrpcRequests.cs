// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Grpc;

/// <summary>
/// Recognizes gRPC calls.
/// </summary>
public static class GrpcRequests
{
    /// <summary>
    /// The content type every gRPC call carries, alone or with a suffix such as <c language="text">+proto</c>.
    /// </summary>
    public const string ContentType = "application/grpc";

    /// <summary>
    /// Whether a request is a gRPC call that arrived on the gRPC listener.
    /// </summary>
    /// <param name="context">The request.</param>
    /// <param name="listenerPort">The gRPC listener's port.</param>
    /// <returns>True when it is.</returns>
    public static bool IsStreamOnListener(HttpContext context, int listenerPort) =>
        context.Connection.LocalPort == listenerPort &&
        HttpProtocol.IsHttp2(context.Request.Protocol) &&
        context.Request.ContentType?.StartsWith(ContentType, StringComparison.OrdinalIgnoreCase) == true;
}
