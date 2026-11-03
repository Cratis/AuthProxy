// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Antiforgery;

namespace Cratis.AuthProxy;

/// <summary>
/// The one antiforgery mechanism the proxy's own state-changing endpoints share.
/// </summary>
/// <remarks>
/// It is the framework's <see cref="IAntiforgery"/> with the proxy's own cookie name and form field, so a
/// feature adds the registration with <see cref="AddProxyAntiforgery"/> and checks a request with
/// <see cref="IsValidAsync"/>. The request token is a form field only: a token in the query string or in a
/// header is never read.
/// </remarks>
public static class ProxyAntiforgery
{
    /// <summary>
    /// The name of the form field that carries the request token.
    /// </summary>
    public const string FormFieldName = "__cratis_antiforgery";

    /// <summary>
    /// Registers the framework antiforgery services with the proxy's cookie and form field.
    /// </summary>
    /// <remarks>
    /// Safe to call from several feature extensions: every call states the same options.
    /// </remarks>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddProxyAntiforgery(this WebApplicationBuilder builder)
    {
        builder.Services.AddAntiforgery(options =>
        {
            options.Cookie.Name = Cookies.Antiforgery;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.Cookie.Path = "/";
            options.FormFieldName = FormFieldName;
            options.HeaderName = null;

            // The page that renders the form owns its framing headers.
            options.SuppressXFrameOptionsHeader = true;
        });

        return builder;
    }

    /// <summary>
    /// Issues the request token for the form being rendered, setting the antiforgery cookie on the response.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>The request token to place in the form field.</returns>
    public static string IssueRequestToken(HttpContext context) =>
        context.RequestServices.GetRequiredService<IAntiforgery>().GetAndStoreTokens(context).RequestToken!;

    /// <summary>
    /// Determines whether the request is a form post that carries a valid antiforgery cookie and token.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns><see langword="true"/> when the request is valid; otherwise <see langword="false"/>.</returns>
    public static async Task<bool> IsValidAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasFormContentType)
        {
            return false;
        }

        try
        {
            return await context.RequestServices.GetRequiredService<IAntiforgery>().IsRequestValidAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            return false;
        }
    }
}
