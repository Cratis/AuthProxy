// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Represents one capability carried to a verifier, together with the two opaque values AuthProxy authored
/// for that presentation.
/// </summary>
/// <param name="Capability">The exact value the caller presented, uninterpreted.</param>
/// <param name="Transaction">The opaque identifier of this presentation, authored by AuthProxy.</param>
/// <param name="Challenge">The independent opaque value bound to this presentation, authored by AuthProxy.</param>
/// <remarks>
/// The transaction and challenge are minted per presentation and never reused. A verifier echoes both back,
/// which is what lets AuthProxy tell an answer to <em>this</em> presentation from an answer to some other
/// one — the reason the answer is not simply a boolean.
/// </remarks>
public sealed record CapabilityPresentation(string Capability, string Transaction, string Challenge);
