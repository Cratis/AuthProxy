// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Cratis.AuthProxy.Identity;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Defines the system that decides when a service is told about a user, and hands the callback to the background delivery.
/// </summary>
/// <remarks>
/// Neither method waits for the service and neither throws: a callback must never block or fail the request it rides on.
/// </remarks>
public interface ISignInCallbackDispatcher
{
    /// <summary>
    /// Reports that a user has just completed an interactive sign-in, to the service that request is for, when that
    /// service has a sign-in callback.
    /// </summary>
    /// <param name="context">The provider-callback request, used to find the service and the tenant.</param>
    /// <param name="user">The principal the provider established.</param>
    /// <param name="scheme">The authentication scheme that produced the principal.</param>
    /// <param name="properties">The properties of the session that is about to be established.</param>
    void SignedIn(HttpContext context, ClaimsPrincipal user, string scheme, AuthenticationProperties? properties);

    /// <summary>
    /// Reports that a user came back with an established session, when this is the first request of that user to the
    /// service within its configured interval.
    /// </summary>
    /// <param name="context">The proxied request.</param>
    /// <param name="serviceName">The configured name of the service the request is for.</param>
    /// <param name="service">The service the request is for.</param>
    /// <param name="principal">The user making the request.</param>
    /// <param name="tenant">The tenant the request resolved, if any.</param>
    void Returned(HttpContext context, string serviceName, Configuration.Service service, ClientPrincipal principal, string? tenant);
}
