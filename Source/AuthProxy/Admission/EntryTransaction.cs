// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Represents AuthProxy-authored state for one admitted entry.
/// </summary>
/// <param name="Transaction">The opaque identifier of the presentation this entry came from.</param>
/// <param name="Challenge">The independent opaque value bound to that presentation.</param>
/// <param name="ExpiresAt">The time at which the entry stops admitting.</param>
/// <remarks>
/// It deliberately does not hold the capability, nor anything derived from it. What is in the browser is
/// the record that a verifier said yes once, not the thing that made it say so.
/// <para>
/// Three fixed-size values, so the sealed cookie has a size the deployment cannot influence. A cookie that
/// grows with what a verifier answered can cross the browser's 4096-byte limit, and a browser drops such a
/// cookie without saying so — which in this mode means an admitted caller silently receiving the uniform
/// refusal for the rest of the entry's life.
/// </para>
/// </remarks>
public sealed record EntryTransaction(
    string Transaction,
    string Challenge,
    DateTimeOffset ExpiresAt);
