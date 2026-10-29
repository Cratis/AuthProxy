// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Describes whether a session records the provider it was signed in with.
/// </summary>
internal enum SessionProviderState
{
    /// <summary>
    /// The session carries exactly one well-formed provider scheme claim.
    /// </summary>
    Recorded = 0,

    /// <summary>
    /// The session carries no claim in the session namespace, as sessions signed in by earlier versions.
    /// </summary>
    Missing = 1,

    /// <summary>
    /// The session carries session claims that are not exactly one well-formed provider scheme claim.
    /// </summary>
    Malformed = 2
}
