// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Identifies the authentication material presented by a request.</summary>
internal static class RequestAuthentication
{
    /// <summary>Determines whether a bearer scheme was presented.</summary>
    /// <param name="request">The current request.</param>
    /// <returns>Whether the authorization headers contain a bearer scheme.</returns>
    internal static bool HasBearer(HttpRequest request) => request.Headers.Authorization
        .SelectMany(value => (value ?? string.Empty).Split(','))
        .Any(value => string.Equals(value.Trim().Split([' ', '\t'], 2)[0], "Bearer", StringComparison.OrdinalIgnoreCase));

    /// <summary>Determines whether the configured authentication cookie was presented.</summary>
    /// <param name="context">The current context.</param>
    /// <returns>Whether the request contains the authentication cookie.</returns>
    internal static bool HasSession(HttpContext context)
    {
        if (context.Request.Cookies.Count == 0) return false;

        var options = context.RequestServices.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        return context.Request.Cookies.ContainsKey(options.Cookie.Name!);
    }
}
