// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// The configured transport protection for an outbound identity-bearing flow.
/// </summary>
public enum BackendHopTransport
{
    /// <summary>No TLS protects the hop.</summary>
    PlainHttp = 0,

    /// <summary>TLS authenticates the server.</summary>
    Tls = 1,

    /// <summary>TLS authenticates the server and offers the proxy's client identity.</summary>
    MutualTls = 2
}
