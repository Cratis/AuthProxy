// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization;

/// <summary>
/// Represents the outcome of evaluating the configured claim requirements for a request.
/// </summary>
/// <param name="IsGranted">Whether the caller satisfies every configured requirement.</param>
/// <param name="UnsatisfiedClaim">
/// The claim type of the first requirement the caller did not satisfy; empty when access is granted.
/// </param>
/// <remarks>
/// The unsatisfied claim is carried so a refusal can be logged as something an operator can act on. A
/// deployment that gates on organization membership and a deployment that gates on a role produce the
/// same <c>403</c>, and "which requirement was it" is the only part that differs and the only part worth
/// looking up. It is deliberately the claim <em>type</em> and never the value the caller carried, which
/// would put an identity into the log.
/// </remarks>
public record AccessDecision(bool IsGranted, string UnsatisfiedClaim)
{
    /// <summary>
    /// Gets the decision for a caller that satisfies everything required of them.
    /// </summary>
    public static AccessDecision Granted { get; } = new(true, string.Empty);

    /// <summary>
    /// Creates the decision for a caller that failed a requirement.
    /// </summary>
    /// <param name="unsatisfiedClaim">The claim type of the requirement that was not satisfied.</param>
    /// <returns>A denied <see cref="AccessDecision"/>.</returns>
    public static AccessDecision Denied(string unsatisfiedClaim) => new(false, unsatisfiedClaim);
}
