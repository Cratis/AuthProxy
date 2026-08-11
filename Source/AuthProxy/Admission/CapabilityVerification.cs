// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Represents a verifier's answer about one <see cref="CapabilityPresentation"/>.
/// </summary>
/// <param name="IsAdmitted">Whether the presented capability admits the caller.</param>
/// <param name="Context">Opaque values the verifier wants carried with the entry, uninterpreted by AuthProxy.</param>
/// <remarks>
/// There is one refusal and no reasons. A verifier that could say <em>why</em> would hand AuthProxy
/// something to say back, and anything said back is the oracle this whole mode exists to remove.
/// </remarks>
public sealed record CapabilityVerification(bool IsAdmitted, IReadOnlyDictionary<string, string> Context)
{
    /// <summary>
    /// The single refusal every unsuccessful outcome resolves to — refused, malformed, unreachable, timed
    /// out or thrown.
    /// </summary>
    public static readonly CapabilityVerification Denied = new(false, EmptyContext);

    static IReadOnlyDictionary<string, string> EmptyContext => new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// Creates an admitting verification.
    /// </summary>
    /// <param name="context">The opaque values to carry with the entry. Defaults to none.</param>
    /// <returns>The admitting <see cref="CapabilityVerification"/>.</returns>
    public static CapabilityVerification Admitted(IReadOnlyDictionary<string, string>? context = null) =>
        new(true, context ?? EmptyContext);
}
