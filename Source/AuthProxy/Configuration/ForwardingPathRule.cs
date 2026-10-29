// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// A literal path rule evaluated against the path forwarded to a service.
/// </summary>
public class ForwardingPathRule
{
    /// <summary>Gets or sets the rooted, service-relative literal path.</summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>Gets or sets whether to match a segment prefix or the exact path.</summary>
    public ForwardingPathMatch Match { get; set; } = ForwardingPathMatch.Prefix;

    /// <summary>Gets or sets HTTP method tokens; an empty list matches every method.</summary>
    /// <remarks>GET also matches HEAD and WebSocket extended CONNECT. No other methods are implied.</remarks>
    public IList<string> Methods { get; set; } = [];
}
