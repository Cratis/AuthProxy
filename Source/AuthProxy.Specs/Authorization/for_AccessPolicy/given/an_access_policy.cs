// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy.given;

/// <summary>
/// A policy and a request to evaluate it against.
/// </summary>
public class an_access_policy : Specification
{
    protected AccessPolicy _policy;
    protected DefaultHttpContext _context;

    void Establish()
    {
        _policy = new AccessPolicy();
        _context = new DefaultHttpContext();
    }

    /// <summary>
    /// Puts an authenticated caller carrying the given claims on the request.
    /// </summary>
    /// <param name="claims">The claims the caller carries.</param>
    protected void CallerCarrying(params Claim[] claims) =>
        _context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "spec"));

    /// <summary>
    /// Builds a configuration declaring proxy-wide requirements.
    /// </summary>
    /// <param name="requirements">The requirements to declare.</param>
    /// <returns>The configuration.</returns>
    protected static C.AuthProxy Requiring(params C.ClaimRequirement[] requirements) =>
        new() { Authorization = new C.Authorization { RequiredClaims = requirements } };

    /// <summary>
    /// Builds a requirement for a claim, optionally narrowed to a set of values.
    /// </summary>
    /// <param name="claim">The claim type.</param>
    /// <param name="anyOf">The values that satisfy it; none requires only presence.</param>
    /// <returns>The requirement.</returns>
    protected static C.ClaimRequirement Claiming(string claim, params string[] anyOf) =>
        new() { Claim = claim, AnyOf = anyOf };
}
