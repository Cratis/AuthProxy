// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Represents the bounded set of reasons an identity verification reached the outcome it did.
/// </summary>
/// <remarks>
/// Deliberately a closed enumeration rather than a message. A denial has to be diagnosable from the log,
/// and the tempting way to make it so is to log what the service actually said — which is a response body
/// from a system that knows who the caller is, and therefore the one thing that must never reach a log
/// sink. Every value here is a code chosen at compile time, so no credential, claim, subject or other
/// personal datum can travel out through this route no matter what a service answers.
/// </remarks>
public enum IdentityVerificationReason
{
    /// <summary>
    /// The service answered with an unambiguous positive verdict.
    /// </summary>
    Verified = 0,

    /// <summary>
    /// The service answered <c>403 Forbidden</c>, refusing the caller outright.
    /// </summary>
    Forbidden = 1,

    /// <summary>
    /// The service answered a well-formed body whose verdict refuses the caller.
    /// </summary>
    NotAuthorized = 2,

    /// <summary>
    /// The service answered a well-formed body whose verdict contradicts itself.
    /// </summary>
    ConflictingVerdict = 3,

    /// <summary>
    /// The service answered a well-formed body carrying no verdict at all.
    /// </summary>
    NoVerdict = 4,

    /// <summary>
    /// The service could not be reached — name resolution, connection, or transport-level failure.
    /// </summary>
    TransportFailure = 5,

    /// <summary>
    /// The service did not answer within the configured verification timeout.
    /// </summary>
    TimedOut = 6,

    /// <summary>
    /// The caller's own request ended before the service answered.
    /// </summary>
    Canceled = 7,

    /// <summary>
    /// The service answered a status code that carries no verdict.
    /// </summary>
    UnsuccessfulStatusCode = 8,

    /// <summary>
    /// The service answered successfully with no body to read a verdict from.
    /// </summary>
    EmptyResponse = 9,

    /// <summary>
    /// The service's answer could not be read or parsed as JSON.
    /// </summary>
    UnreadableResponse = 10
}
