// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// The HTTP version the proxy speaks to a service endpoint.
/// </summary>
public enum BackendProtocol
{
    /// <summary>
    /// HTTP/2 where the endpoint negotiates it over TLS, HTTP/1.1 otherwise - what every endpoint did before this
    /// setting existed.
    /// </summary>
    Default = 0,

    /// <summary>
    /// HTTP/2 only, also over plain HTTP. Required for gRPC, whose streams and trailers HTTP/1.1 cannot carry.
    /// </summary>
    Http2 = 1,
}
