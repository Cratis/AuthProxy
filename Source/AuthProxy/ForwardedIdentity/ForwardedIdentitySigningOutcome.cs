// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Describes an outbound signing decision.</summary>
public enum ForwardedIdentitySigningOutcome
{
    /// <summary>The flow remains in unsigned legacy mode.</summary>
    NotConfigured = 0,

    /// <summary>A fresh proof was attached.</summary>
    SignatureCreated = 1,

    /// <summary>No authenticated identity material needs a proof.</summary>
    NotIdentityBearing = 2,

    /// <summary>The opted-in identity-bearing request must not be sent.</summary>
    Refused = 3
}
