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

    /// <summary>Determines whether authentication material is ambiguous.</summary>
    /// <param name="context">The current context.</param>
    /// <returns>Whether the request combines authentication types or authorization values.</returns>
    internal static bool IsAmbiguous(HttpContext context)
    {
        var mixed = HasBearer(context.Request) && HasSession(context);
        return mixed || HasMultipleAuthorization(context.Request);
    }

    /// <summary>Determines whether more than one authorization value was presented.</summary>
    /// <param name="request">The current request.</param>
    /// <returns>Whether the authorization header is repeated or combined.</returns>
    internal static bool HasMultipleAuthorization(HttpRequest request) => request.Headers.Authorization.Count > 1
        || request.Headers.Authorization.Any(value => value?.Contains(',') == true);

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
