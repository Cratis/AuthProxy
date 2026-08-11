// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Represents a verifier's answer about one <see cref="CapabilityPresentation"/>.
/// </summary>
/// <param name="IsAdmitted">Whether the presented capability admits the caller.</param>
/// <remarks>
/// There is one refusal and no reasons. A verifier that could say <em>why</em> would hand AuthProxy
/// something to say back, and anything said back is the oracle this whole mode exists to remove.
/// <para>
/// A yes carries nothing beyond itself either. Anything a verifier could ask to have carried alongside the
/// entry would be sealed into a cookie of unbounded size, and a cookie past the browser's 4096-byte limit
/// is dropped silently — leaving a caller who was admitted receiving the uniform refusal forever, with
/// nothing said anywhere about why. The value has to be earned before it is carried.
/// </para>
/// </remarks>
public sealed record CapabilityVerification(bool IsAdmitted)
{
    /// <summary>
    /// The single refusal every unsuccessful outcome resolves to — refused, malformed, unreachable, timed
    /// out or thrown.
    /// </summary>
    public static readonly CapabilityVerification Denied = new(false);

    /// <summary>
    /// The single admitting answer.
    /// </summary>
    public static readonly CapabilityVerification Admitted = new(true);
}
