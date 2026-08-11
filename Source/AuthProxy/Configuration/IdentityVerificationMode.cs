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
    /// The endpoint enriches identity details, and only an HTTP <c>403</c> refuses the caller. Every other
    /// answer lets the request through and merges whatever details came with it — an unreachable service, a
    /// timeout, a non-success status other than <c>403</c>, an empty body, an unparseable body, and a
    /// well-formed body whose own <c>isAuthorized</c> or <c>isAuthenticated</c> verdict is negative or
    /// self-contradicting. This is the released behavior, exactly, and remains the default.
    /// </summary>
    /// <remarks>
    /// The released call read no verdict out of the body at all, so a body-level negative is admitted here
    /// on purpose rather than by omission. A deployment whose service answers with a verdict it wants
    /// enforced says so with <see cref="Required"/>; promoting the verdict in this mode would change what an
    /// unchanged configuration does to an unchanged service.
    /// </remarks>
    BestEffort = 0,

    /// <summary>
    /// The endpoint is an authorization decision, and only an explicit positive lets the request through.
    /// Anything else — an unreachable service, a timeout, a cancellation, any non-success status, an empty
    /// or unparseable body, or a well-formed body carrying no unambiguous positive — denies the request,
    /// clears any remembered authorization, and serves the forbidden page.
    /// </summary>
    /// <remarks>
    /// A denial expires the readable identity cookie and the sealed authorization record by asking the
    /// browser to delete them, and evicts the in-memory result. Two of those three are requests rather than
    /// guarantees: a non-browser caller that ignores <c>Set-Cookie</c> keeps presenting the sealed record it
    /// was issued and is short-circuited on it until it expires. So what this mode bounds is revocation
    /// <em>latency</em> — a positive can be reused for at most
    /// <see cref="Session.IdentityRevalidationInterval"/> (the sealed record) or
    /// <see cref="Session.IdentityResultCacheDuration"/> (the proxy's own cache), and no longer. Set the
    /// re-validation interval to zero to have no record sealed at all, which is what makes every request
    /// verified.
    /// </remarks>
    Required = 1
}
