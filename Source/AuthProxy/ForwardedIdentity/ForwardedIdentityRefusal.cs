// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Identifies a bounded, non-sensitive reason a request cannot be signed.</summary>
internal enum ForwardedIdentityRefusal
{
    /// <summary>No refusal.</summary>
    None = 0,

    /// <summary>No final absolute outbound address.</summary>
    NoAbsoluteAddress = 1,

    /// <summary>The HTTP method is not an uppercase token.</summary>
    InvalidMethod = 2,

    /// <summary>The escaped path is malformed.</summary>
    InvalidPath = 3,

    /// <summary>A covered header has multiple values.</summary>
    RepeatedHeader = 4,

    /// <summary>A covered value contains forbidden characters.</summary>
    InvalidHeaderValue = 5,

    /// <summary>A required principal field is absent or empty.</summary>
    IncompleteIdentity = 6,

    /// <summary>The covered-header limit was exceeded.</summary>
    TooManyHeaders = 7,

    /// <summary>The canonical byte limit was exceeded.</summary>
    CanonicalTooLarge = 8
}
