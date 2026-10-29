// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware.given;

/// <summary>
/// Provides a selected-tenant cookie shared by the middleware under test and the requests that carry its value.
/// </summary>
public static class signed_selected_tenant_cookies
{
    /// <summary>
    /// Gets the cookie handler the middleware under test is built with.
    /// </summary>
    public static readonly SelectedTenantCookie Instance = new(new EphemeralDataProtectionProvider());

    /// <summary>
    /// Makes the request carry a signed selected-tenant cookie for the signed-in account of the context.
    /// </summary>
    /// <param name="context">The context of the request.</param>
    /// <param name="tenantId">The tenant the cookie names.</param>
    public static void Seed(DefaultHttpContext context, string tenantId)
    {
        var writer = new DefaultHttpContext { User = context.User, RequestServices = context.RequestServices };
        Instance.TryWrite(writer, tenantId).ShouldBeTrue();
        Append(context, Value(writer));
    }

    /// <summary>
    /// Makes the request carry a selected-tenant cookie holding a plain tenant identifier, as earlier versions wrote.
    /// </summary>
    /// <param name="context">The context of the request.</param>
    /// <param name="tenantId">The tenant the cookie names.</param>
    public static void SeedLegacy(DefaultHttpContext context, string tenantId) =>
        Append(context, $"{Cookies.Tenant}={tenantId}");

    /// <summary>
    /// Reads back, for the signed-in account of the context, the selected-tenant cookie its response set.
    /// </summary>
    /// <param name="context">The context holding the response.</param>
    /// <returns>What the cookie holds for that account.</returns>
    public static SelectedTenantCookieValue ReadBack(DefaultHttpContext context)
    {
        var reader = new DefaultHttpContext { User = context.User, RequestServices = context.RequestServices };
        reader.Request.Headers.Cookie = Value(context);
        return Instance.Read(reader);
    }

    /// <summary>
    /// Gets the selected-tenant cookie the response of a context set, as a request cookie header value.
    /// </summary>
    /// <param name="context">The context holding the response.</param>
    /// <returns>The cookie header value.</returns>
    public static string Value(HttpContext context)
    {
        var header = context.Response.Headers.SetCookie.ToString();
        var start = header.IndexOf($"{Cookies.Tenant}=", StringComparison.Ordinal);
        var end = header.IndexOf(';', start);
        return header[start..end];
    }

    /// <summary>
    /// Adds a cookie to the request, keeping the cookies it already carries.
    /// </summary>
    /// <param name="context">The context of the request.</param>
    /// <param name="cookie">The cookie as <c language="text">name=value</c>.</param>
    public static void Append(DefaultHttpContext context, string cookie)
    {
        var existing = context.Request.Headers.Cookie.ToString();
        context.Request.Headers.Cookie = existing.Length == 0 ? cookie : $"{existing}; {cookie}";
    }
}
