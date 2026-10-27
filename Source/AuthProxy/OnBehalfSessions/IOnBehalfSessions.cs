// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Defines how on-behalf sessions are started, re-checked and ended.
/// </summary>
public interface IOnBehalfSessions
{
    /// <summary>
    /// Starts an on-behalf session for the signed-in caller, if the application confirms a live grant and
    /// acknowledges the start. On success the session cookie is written to the response.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="request">What the caller asked to start.</param>
    /// <returns>The <see cref="OnBehalfStartResult"/>.</returns>
    Task<OnBehalfStartResult> Start(HttpContext context, OnBehalfStartRequest request);

    /// <summary>
    /// Works out the on-behalf state of a request, re-checking the grant when the remembered answer is stale and
    /// ending the session when it may no longer continue.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>The <see cref="OnBehalfResolution"/>.</returns>
    Task<OnBehalfResolution> Resolve(HttpContext context);

    /// <summary>
    /// Ends the on-behalf session the request carries, if any, notifies the application and removes the cookie.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="reason">Why it ends.</param>
    /// <returns>The <see cref="OnBehalfEndStatus"/>.</returns>
    Task<OnBehalfEndStatus> End(HttpContext context, OnBehalfSessionEndReason reason);
}
