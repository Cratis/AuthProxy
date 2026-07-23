// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Defines a system that notifies the application when a user completes an interactive sign-in, so the
/// application can record it.
/// </summary>
public interface ISignInNotifier
{
    /// <summary>
    /// Posts a completed sign-in for the freshly authenticated <paramref name="principal"/> to the
    /// application's configured notification endpoint, together with the approximate location and browser
    /// information derived from <paramref name="context"/>.
    /// </summary>
    /// <param name="context">The provider-callback request, used to derive the client's location and browser.</param>
    /// <param name="principal">The principal established by the identity-provider authentication.</param>
    /// <returns>The <see cref="SignInNotificationResult"/> describing the outcome.</returns>
    /// <remarks>
    /// Recording a sign-in must never break the sign-in itself, so an implementation is expected to be fully
    /// resilient — it reports failures through the returned result rather than throwing.
    /// </remarks>
    Task<SignInNotificationResult> Notify(HttpContext context, ClaimsPrincipal? principal);
}
