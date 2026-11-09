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
/// can hand one caller's refusal to another. The response body is a fixed JSON error code, never markup; why a
/// token was refused is logged, never told to the caller. A route that accepts personal access tokens only names a
/// realm and advertises no OAuth metadata.
/// <para>
/// <c language="text">resource_metadata</c> is only ever advertised by a route whose profile accepts OAuth tokens.
/// </para>
/// </remarks>
public static class BearerChallenge
{
    /// <summary>
    /// The seconds a client is asked to wait when the issuer's keys could not be retrieved.
    /// </summary>
    public const int IssuerUnavailableRetryAfterSeconds = 30;

    /// <summary>
    /// The status of a request that presents more than one credential (RFC 6750 §3.1: <c language="text">invalid_request</c>).
    /// </summary>
    public const int MultipleCredentialsStatusCode = StatusCodes.Status400BadRequest;

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
                Refuse(context, StatusCodes.Status401Unauthorized, "unauthorized", RouteChallenge(route, error: null, scope: null));
                break;

            case BearerTokenValidationStatus.InsufficientScope:
                Refuse(
                    context,
                    StatusCodes.Status403Forbidden,
                    "insufficient_scope",
                    RouteChallenge(route, "insufficient_scope", string.Join(' ', BearerTokenValidator.RequiredScopes(route))));
                break;

            case BearerTokenValidationStatus.MissingTenant:
            case BearerTokenValidationStatus.UnboundCredential:
                Forbidden(context);
                break;

            case BearerTokenValidationStatus.IssuerUnavailable:
            case BearerTokenValidationStatus.IntrospectionUnavailable:
                // The token could not be checked, which is not the same as the token being wrong: telling the
                // client its token is invalid would send it to sign in again for an outage on the issuer's side.
                NoStore(context);
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.Headers.RetryAfter = IssuerUnavailableRetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
                MachineResponse.Write(context, StatusCodes.Status503ServiceUnavailable, "service_unavailable");
                break;

            // Revoked is answered exactly like Invalid, so the response is no revocation oracle.
            default:
                Refuse(context, StatusCodes.Status401Unauthorized, "unauthorized", RouteChallenge(route, "invalid_token", scope: null));
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
        Refuse(context, StatusCodes.Status401Unauthorized, "unauthorized", ChallengeValue(resourceMetadataUrl, error, scope: null));

    /// <summary>
    /// Writes a bare <c language="text">403</c>: the token is valid, and the request is still refused.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    public static void Forbidden(HttpContext context)
    {
        NoStore(context);
        MachineResponse.Write(context, StatusCodes.Status403Forbidden, "forbidden");
    }

    /// <summary>
    /// Refuses a request that presented more than one credential, without choosing between them.
    /// </summary>
    /// <param name="context">The request context.</param>
    public static void MultipleCredentials(HttpContext context) =>
        Refuse(context, MultipleCredentialsStatusCode, "invalid_request", ChallengeValue(resourceMetadataUrl: null, "invalid_request", scope: null));

    /// <summary>
    /// Writes a bare <c language="text">400</c>: the request path is not one AuthProxy will vouch for a principal on.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    public static void BadRequest(HttpContext context)
    {
        NoStore(context);
        MachineResponse.Write(context, StatusCodes.Status400BadRequest, "invalid_request");
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

    /// <summary>
    /// Writes a <c language="text">404</c> for a resource-metadata request on a route that advertises none.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    internal static void MetadataNotFound(HttpContext context)
    {
        NoStore(context);
        MachineResponse.Write(context, StatusCodes.Status404NotFound, "not_found");
    }

    /// <summary>
    /// Writes a <c language="text">405</c> naming the methods a resource-metadata request may use.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    internal static void MethodNotAllowed(HttpContext context)
    {
        NoStore(context);
        context.Response.Headers[HeaderNames.Allow] = "GET, HEAD";
        MachineResponse.Write(context, StatusCodes.Status405MethodNotAllowed, "method_not_allowed");
    }

    /// <summary>
    /// Prevents caching a bearer-route refusal.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    internal static void NoStore(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers[HeaderNames.Pragma] = "no-cache";
    }

    /// <summary>
    /// Builds the challenge a route advertises for its profile.
    /// </summary>
    /// <param name="route">The route the request was made on.</param>
    /// <param name="error">The RFC 6750 error code, if any.</param>
    /// <param name="scope">The scopes the request needs, if any.</param>
    /// <returns>The header value.</returns>
    /// <remarks>
    /// A personal-access-token-only route names its realm and nothing else. A realm that is missing or is not a
    /// plain resource key is left out rather than quoted, so the challenge can neither break out of its parameter
    /// nor fall back to advertising OAuth metadata.
    /// </remarks>
    static string RouteChallenge(ResolvedBearerRoute route, string? error, string? scope)
    {
        if (route.Profile != BearerProfile.PatOnly)
        {
            return ChallengeValue(route.ResourceMetadataUrl, error, scope);
        }

        return IsPlainKey(route.ResourceKey) ? $"Bearer realm=\"{route.ResourceKey}\"" : "Bearer";
    }

    static bool IsPlainKey(string? key) =>
        !string.IsNullOrEmpty(key) && key.All(character => character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-');

    static void Refuse(HttpContext context, int statusCode, string code, string challenge)
    {
        NoStore(context);
        context.Response.Headers.WWWAuthenticate = challenge;
        MachineResponse.Write(context, statusCode, code);
    }
}
