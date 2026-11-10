// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>The verified proof fields, never a forwarded authentication verdict by themselves.</summary>
/// <param name="Status">The outcome.</param>
/// <param name="Reason">The fixed refusal code.</param>
/// <param name="Jkt">The verified thumbprint.</param>
/// <param name="Jti">The bounded proof identifier.</param>
/// <param name="Nonce">The optional nonce awaiting verification.</param>
internal sealed record DpopProofResult(DpopProofStatus Status, string Reason, string? Jkt = null, string? Jti = null, string? Nonce = null)
{
    /// <summary>Creates a refusal without exposing untrusted values.</summary>
    /// <param name="reason">The fixed reason code.</param>
    /// <returns>The refusal.</returns>
    internal static DpopProofResult Invalid(string reason) => new(DpopProofStatus.Invalid, reason);
}
