// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Represents what a single service's identity endpoint actually established about a caller.
/// </summary>
/// <remarks>
/// The three states exist because "not a positive" and "a negative" are different facts, and collapsing
/// them is what let a failed call read as a successful one. A service that refuses has decided something; a
/// service that could not be reached has decided nothing. Which of the two denies the request is a
/// deployment's choice, expressed through
/// <see cref="Configuration.IdentityVerificationMode"/> — but the distinction itself has to survive the
/// call, or the choice cannot be made.
/// </remarks>
public enum IdentityVerificationStatus
{
    /// <summary>
    /// The service established nothing. The call failed, timed out, was cancelled, answered a status that
    /// carries no verdict, or answered a body carrying no unambiguous positive.
    /// </summary>
    Indeterminate = 0,

    /// <summary>
    /// The service answered with an unambiguous positive verdict for this caller.
    /// </summary>
    Positive = 1,

    /// <summary>
    /// The service explicitly refused this caller.
    /// </summary>
    Denied = 2
}
