// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Represents AuthProxy-authored state for one admitted entry.
/// </summary>
/// <param name="Transaction">The opaque identifier of the presentation this entry came from.</param>
/// <param name="Challenge">The independent opaque value bound to that presentation.</param>
/// <param name="ExpiresAt">The time at which the entry stops admitting.</param>
/// <param name="Context">The opaque values the verifier asked to have carried, uninterpreted by AuthProxy.</param>
/// <remarks>
/// It deliberately does not hold the capability, nor anything derived from it. What is in the browser is
/// the record that a verifier said yes once, not the thing that made it say so.
/// </remarks>
public sealed record EntryTransaction(
    string Transaction,
    string Challenge,
    DateTimeOffset ExpiresAt,
    IReadOnlyDictionary<string, string> Context);
