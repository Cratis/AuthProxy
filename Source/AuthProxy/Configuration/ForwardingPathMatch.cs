// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Describes how a service-relative forwarding path is matched.
/// </summary>
public enum ForwardingPathMatch
{
    /// <summary>Match the path and its descendants on segment boundaries.</summary>
    Prefix = 0,

    /// <summary>Match only the path, ignoring a single trailing slash.</summary>
    Exact = 1
}
