// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>Identifies why a configured forwarding rule cannot be honored.</summary>
public enum ForwardingPathEntryRejection
{
    /// <summary>The entry is valid.</summary>
    None = 0,

    /// <summary>The path is empty.</summary>
    Empty = 1,

    /// <summary>The path is not rooted.</summary>
    NotRooted = 2,

    /// <summary>The path contains whitespace.</summary>
    Whitespace = 3,

    /// <summary>The path contains a nonliteral character.</summary>
    DisallowedCharacter = 4,

    /// <summary>The path contains an empty segment.</summary>
    EmptySegment = 5,

    /// <summary>The path contains a dot or dot-dot segment.</summary>
    DotSegment = 6,

    /// <summary>A prefix rule would match every path.</summary>
    RootPrefix = 7,

    /// <summary>The match kind is unknown.</summary>
    InvalidMatch = 8,

    /// <summary>A method is not an ASCII HTTP token.</summary>
    InvalidMethod = 9,

    /// <summary>A path segment ends in a dot that an origin could trim.</summary>
    TrailingDot = 10
}
