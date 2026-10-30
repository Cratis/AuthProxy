// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Represents the outcome of evaluating an existing session cookie against the canonical identity rules.
/// </summary>
/// <remarks>
/// These are internal decisions, not logged, serialized or externally visible error codes.
/// </remarks>
enum CanonicalSessionVerdict
{
    /// <summary>
    /// The session carries no canonical state and is not tied to a canonical provider; it is accepted.
    /// </summary>
    Legacy = 0,

    /// <summary>
    /// The session's canonical claims and stored registration match the current registration; it is accepted.
    /// </summary>
    Current = 1,

    /// <summary>
    /// The session carries no canonical state but was established by a provider that is now canonical; it is rejected.
    /// </summary>
    LegacySessionForCanonicalProvider = 2,

    /// <summary>
    /// The authentication configuration is invalid while evaluating the session; it is rejected.
    /// </summary>
    ConfigurationInvalid = 3,

    /// <summary>
    /// The session carries registration state but no canonical claims; it is rejected.
    /// </summary>
    MissingCanonicalClaims = 4,

    /// <summary>
    /// The stored registration state is duplicated, malformed or lacks the provider scheme; it is rejected.
    /// </summary>
    MalformedRegistrationState = 5,

    /// <summary>
    /// The canonical identity can no longer be resolved for the session; it is rejected.
    /// </summary>
    UnresolvedIdentity = 6,

    /// <summary>
    /// The provider registration has changed since the session was established; it is rejected.
    /// </summary>
    RegistrationChanged = 7
}
