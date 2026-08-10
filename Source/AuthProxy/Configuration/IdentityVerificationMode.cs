// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents what a service's answer on <c>/.cratis/me</c> means to AuthProxy.
/// </summary>
/// <remarks>
/// Calling the identity endpoint answers two different questions at once, and they have opposite failure
/// directions. <em>Enrichment</em> asks "what else does this service know about the signed-in user", and the
/// right answer to an unreachable service is to carry on without the extra details. <em>Verification</em>
/// asks "is this user allowed in at all", and the only safe answer to an unreachable service is no.
/// <para>
/// Because a single boolean cannot express both, this names which question a service is being asked. It is
/// deliberately a mode rather than a flag: a deployment that later needs a third answer — auditing a denial
/// without enforcing it, say — gets a new member instead of a second boolean whose combination with the
/// first nobody can reason about.
/// </para>
/// <para>
/// This is orthogonal to <see cref="Service.ResolveIdentityDetails"/>, which decides whether the endpoint is
/// called at all. This decides what the answer means once it arrives.
/// </para>
/// </remarks>
public enum IdentityVerificationMode
{
    /// <summary>
    /// The endpoint enriches identity details, and any answer that is not an explicit refusal lets the
    /// request through. An unreachable service, a timeout, a non-success status other than <c>403</c>, an
    /// empty body and an unparseable body all resolve to "no extra details" rather than to a refusal. This
    /// is the released behavior and remains the default.
    /// </summary>
    BestEffort = 0,

    /// <summary>
    /// The endpoint is an authorization decision, and only an explicit positive lets the request through.
    /// Anything else — an unreachable service, a timeout, a cancellation, any non-success status, an empty
    /// or unparseable body, or a well-formed body carrying no unambiguous positive — denies the request,
    /// clears any remembered authorization, and serves the forbidden page.
    /// </summary>
    Required = 1
}
