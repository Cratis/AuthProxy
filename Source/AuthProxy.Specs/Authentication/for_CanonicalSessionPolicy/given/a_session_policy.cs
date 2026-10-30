// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;

/// <summary>
/// Provides the canonical registration fixture and evaluates sessions directly through the policy.
/// </summary>
public class a_session_policy : canonical_cookie_registration
{
    internal CanonicalSessionVerdict Evaluate(ClaimsPrincipal principal, AuthenticationProperties properties) =>
        CanonicalSessionPolicy.Evaluate(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme, _services);
}
