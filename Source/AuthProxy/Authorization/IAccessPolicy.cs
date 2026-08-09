// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>
/// Defines the policy deciding whether an authenticated caller may pass the proxy at all.
/// </summary>
public interface IAccessPolicy
{
    /// <summary>
    /// Determines whether the configuration declares anything to authorize against.
    /// </summary>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when at least one requirement is declared; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Nothing declared is the state every deployment that never opts in is in, and it has to stay
    /// indistinguishable from this feature not existing. Asking first keeps the whole evaluation — and the
    /// question of which service a request targets — off the path of a deployment that does not use it.
    /// </remarks>
    bool IsConfigured(C.AuthProxy config);

    /// <summary>
    /// Evaluates the configured claim requirements against the caller on the current request.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>, carrying the authenticated principal.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The <see cref="AccessDecision"/> for this caller and request.</returns>
    AccessDecision Evaluate(HttpContext context, C.AuthProxy config);
}
