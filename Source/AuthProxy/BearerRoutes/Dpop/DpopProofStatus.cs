// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>The outcome of cryptographic proof verification.</summary>
internal enum DpopProofStatus
{
    /// <summary>The proof was refused.</summary>
    Invalid = 0,

    /// <summary>The proof verified; nonce and replay consumption are still required.</summary>
    Valid = 1,
}
