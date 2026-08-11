// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Represents the verifier's reply about one presentation.
/// </summary>
/// <param name="Admitted">Whether the capability admits the caller.</param>
/// <param name="Transaction">The transaction the verifier is answering about.</param>
/// <param name="Challenge">The challenge the verifier is answering about.</param>
/// <remarks>
/// The transaction and challenge are echoed rather than assumed. A reply that does not name the exact
/// presentation it belongs to is not an answer to it, and treating it as one would let a reply meant for
/// some other presentation admit this caller.
/// <para>
/// Three fields and no more. Anything else a reply carries is read past without being bound, so a verifier
/// that says more than yes-about-this-presentation cannot make AuthProxy hold it, seal it into a browser or
/// hand it on.
/// </para>
/// </remarks>
public sealed record CapabilityVerificationResponse(
    bool Admitted,
    string? Transaction,
    string? Challenge);
