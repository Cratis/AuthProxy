// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Decides whether a presented capability admits the caller.
/// </summary>
/// <remarks>
/// The whole point of the seam is that AuthProxy never learns what a capability means. It reads a value,
/// carries it here, and does what it is told — so the deployment owns issuance, revocation, single use and
/// every other rule, and none of that vocabulary reaches the proxy.
/// </remarks>
public interface ICapabilityVerifier
{
    /// <summary>
    /// Verifies one presentation.
    /// </summary>
    /// <param name="presentation">The capability and the opaque values authored for this presentation.</param>
    /// <param name="cancellationToken">The token that aborts the verification.</param>
    /// <returns>The <see cref="CapabilityVerification"/> for this presentation.</returns>
    /// <remarks>
    /// An implementation never throws for a refusal, and every failure it cannot classify is a refusal:
    /// the mode is worth nothing if an unreachable verifier lets callers in.
    /// </remarks>
    Task<CapabilityVerification> Verify(CapabilityPresentation presentation, CancellationToken cancellationToken);
}
