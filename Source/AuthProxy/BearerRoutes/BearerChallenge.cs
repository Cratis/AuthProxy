// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Writes the API-style refusals of a bearer route: RFC 6750 challenges carrying the RFC 9728
/// <c language="text">resource_metadata</c> parameter an MCP client discovers its authorization server from.
/// </summary>
/// <remarks>
/// Never a redirect and never a page: a bearer route is called by programs, and a program told to go and sign
/// in somewhere has nothing to do with the answer. Every refusal is marked <c language="text">no-store</c> so no cache
/// can hand one caller's refusal to another. The response body is empty; why a token was refused is logged,
/// never told to the caller.
/// </remarks>
public static class BearerChallenge
{
    /// <summary>
    /// The seconds a client is asked to wait when the issuer's keys could not be retrieved.
    /// </summary>
    public const int IssuerUnavailableRetryAfterSeconds = 30;

    /// <summary>
    /// Writes the refusal matching a failed validation.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="validation">The failed validation.</param>
    /// <param name="route">The route the token was presented on.</param>
    public static void Write(HttpContext context, BearerTokenValidation validation, ResolvedBearerRoute route)
    {
        switch (validation.Status)
        {
            case BearerTokenValidationStatus.Missing:
                // RFC 6750 §3.1: a request that carried no credentials gets no error code.
                Unauthorized(context, route.ResourceMetadataUrl, error: null);
                break;

            case BearerTokenValidationStatus.InsufficientScope:
                Challenge(
                    context,
                    StatusCodes.Status403Forbidden,
                    route.ResourceMetadataUrl,
                    "insufficient_scope",
                    string.Join(' ', BearerTokenValidator.RequiredScopes(route)));
                break;

            case BearerTokenValidationStatus.MissingTenant:
                Forbidden(context);
                break;

            case BearerTokenValidationStatus.IssuerUnavailable:
                // The token could not be checked, which is not the same as the token being wrong: telling the
                // client its token is invalid would send it to sign in again for an outage on the issuer's side.
                NoStore(context);
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.Headers.RetryAfter = IssuerUnavailableRetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
                break;

            default:
                Unauthorized(context, route.ResourceMetadataUrl, "invalid_token");
                break;
        }
    }

    /// <summary>
    /// Writes a <c language="text">401</c> challenge.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="resourceMetadataUrl">The protected-resource metadata URL to name, if any.</param>
    /// <param name="error">The RFC 6750 error code, or <see langword="null"/> for a request that carried no token.</param>
    public static void Unauthorized(HttpContext context, Uri? resourceMetadataUrl, string? error) =>
        Challenge(context, StatusCodes.Status401Unauthorized, resourceMetadataUrl, error, scope: null);

    /// <summary>
    /// Writes a bare <c language="text">403</c>: the token is valid, and the request is still refused.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    public static void Forbidden(HttpContext context)
    {
        NoStore(context);
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
    }

    /// <summary>
    /// Builds the value of a <c language="text">WWW-Authenticate</c> bearer challenge.
    /// </summary>
    /// <param name="resourceMetadataUrl">The protected-resource metadata URL to name, if any.</param>
    /// <param name="error">The RFC 6750 error code, if any.</param>
    /// <param name="scope">The scopes the request needs, if any.</param>
    /// <returns>The header value.</returns>
    /// <remarks>
    /// Every value placed in a quoted string here is either a constant, a URL that was parsed as an absolute URI
    /// at startup, or a scope validated against the RFC 6749 scope-token grammar — none can carry a quote or a
    /// backslash, so none can break out of its parameter.
    /// </remarks>
    public static string ChallengeValue(Uri? resourceMetadataUrl, string? error, string? scope)
    {
        var parameters = new List<string>();
        if (error is not null)
        {
            parameters.Add($"error=\"{error}\"");
        }

        if (!string.IsNullOrEmpty(scope))
        {
            parameters.Add($"scope=\"{scope}\"");
        }

        if (resourceMetadataUrl is not null)
        {
            parameters.Add($"resource_metadata=\"{resourceMetadataUrl.AbsoluteUri}\"");
        }

        return parameters.Count == 0 ? "Bearer" : $"Bearer {string.Join(", ", parameters)}";
    }

    static void Challenge(HttpContext context, int statusCode, Uri? resourceMetadataUrl, string? error, string? scope)
    {
        NoStore(context);
        context.Response.StatusCode = statusCode;
        context.Response.Headers.WWWAuthenticate = ChallengeValue(resourceMetadataUrl, error, scope);
    }

    static void NoStore(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers[HeaderNames.Pragma] = "no-cache";
    }
}
