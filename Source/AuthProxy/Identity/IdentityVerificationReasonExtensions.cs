// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Extension methods for <see cref="IdentityVerificationReason"/>.
/// </summary>
public static class IdentityVerificationReasonExtensions
{
    /// <summary>
    /// Gets whether the reason says verification could not be completed - the service was unreachable, slow or answered
    /// something unusable - as opposed to the service answering that the caller may not enter.
    /// </summary>
    /// <param name="reason">The reason.</param>
    /// <returns>True when verification was unavailable, false when the caller was actually refused.</returns>
    /// <remarks>
    /// An unavailable service is an outage, not a verdict. Telling the person "access denied" is untrue, and ending
    /// their session over it makes the outage worse.
    /// </remarks>
    public static bool IsUnavailable(this IdentityVerificationReason reason) => reason is
        IdentityVerificationReason.TransportFailure or
        IdentityVerificationReason.TimedOut or
        IdentityVerificationReason.UnsuccessfulStatusCode or
        IdentityVerificationReason.EmptyResponse or
        IdentityVerificationReason.UnreadableResponse or
        IdentityVerificationReason.OnBehalfAssertionUnavailable;
}
