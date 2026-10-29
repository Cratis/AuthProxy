// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>Identifies why a request cannot be forwarded.</summary>
public enum ForwardingPathRefusal
{
    /// <summary>Forwarding is permitted.</summary>
    None = 0,

    /// <summary>A deny rule matched.</summary>
    Denied = 1,

    /// <summary>No allow rule matched, or the rules are invalid.</summary>
    NotAllowed = 2,

    /// <summary>The path cannot be interpreted unambiguously.</summary>
    NonCanonicalPath = 3,

    /// <summary>A method-override header is present.</summary>
    MethodOverride = 4,

    /// <summary>No configured service corresponds to the selected route.</summary>
    UnresolvedService = 5
}
