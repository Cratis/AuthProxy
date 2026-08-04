// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Provides helper methods for classifying well-known AuthProxy HTTP requests.
/// </summary>
public static class HttpContextExtensions
{
    const string SignInPathPrefix = "/signin-";
    const string FetchDestinationHeader = "Sec-Fetch-Dest";
    const string HtmlMediaType = "text/html";

    /// <summary>
    /// Gets the current request path and query string as a single relative URL.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns>The current request path and query string.</returns>
    public static string GetPathAndQuery(this HttpContext context) => $"{context.Request.Path}{context.Request.QueryString}";

    /// <summary>
    /// Determines whether the request has a pending invitation cookie.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if a pending invitation cookie exists; otherwise <see langword="false"/>.</returns>
    public static bool HasPendingInvitation(this HttpContext context) => context.Request.Cookies.ContainsKey(Cookies.InviteToken);

    /// <summary>
    /// Determines whether the request has a pending registration cookie.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if a pending registration cookie exists; otherwise <see langword="false"/>.</returns>
    public static bool HasPendingRegistration(this HttpContext context) => context.Request.Cookies.ContainsKey(Cookies.Registration);

    /// <summary>
    /// Determines whether the request targets an invitation URL.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is an invitation URL; otherwise <see langword="false"/>.</returns>
    public static bool IsInvitation(this HttpContext context) => context.Request.Path.StartsWithSegments(WellKnownPaths.InvitePathPrefix);

    /// <summary>
    /// Determines whether the request targets the registration URL.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is a registration URL; otherwise <see langword="false"/>.</returns>
    public static bool IsRegistration(this HttpContext context) => context.Request.Path.StartsWithSegments(WellKnownPaths.Registration);

    /// <summary>
    /// Determines whether the request targets one of the login endpoints.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is a login endpoint; otherwise <see langword="false"/>.</returns>
    public static bool IsLogin(this HttpContext context) =>
        context.Request.Path.StartsWithSegments(WellKnownPaths.LoginPrefix)
        || context.Request.Path.StartsWithSegments(WellKnownPaths.LoginPage);

    /// <summary>
    /// Determines whether the request targets the well-known providers endpoint.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request targets the providers endpoint; otherwise <see langword="false"/>.</returns>
    public static bool IsProviders(this HttpContext context) => context.Request.Path.StartsWithSegments(WellKnownPaths.Providers);

    /// <summary>
    /// Determines whether the request targets the well-known client-credentials token endpoint.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request targets the token endpoint; otherwise <see langword="false"/>.</returns>
    public static bool IsToken(this HttpContext context) => context.Request.Path.StartsWithSegments(WellKnownPaths.Token);

    /// <summary>
    /// Determines whether the request targets the AuthProxy authentication user interface.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is part of the authentication UI; otherwise <see langword="false"/>.</returns>
    public static bool IsAuthenticationUI(this HttpContext context) => context.IsLogin() || context.IsProviders() || context.IsToken();

    /// <summary>
    /// Determines whether the request targets a path a service declares as anonymous.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <param name="config">The auth proxy configuration declaring the anonymous paths.</param>
    /// <returns><see langword="true"/> if the request targets an anonymous path; otherwise <see langword="false"/>.</returns>
    public static bool IsAnonymousPath(this HttpContext context, C.AuthProxy config) =>
        AnonymousPaths.Matches(context.Request.Path, config);

    /// <summary>
    /// Determines whether the request is a browser navigating to a document, and therefore a request an
    /// HTML page is an answer to.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if an HTML page answers the request; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// AuthProxy refuses unauthenticated callers by writing a page — provider selection, tenant selection —
    /// and a page has to be delivered with a success status to render. That is the right answer to a person
    /// in a browser and the wrong answer to everything else: a webhook or an integration reads the
    /// <c>200</c> as delivered and never retries, and a frontend's <c>fetch()</c> passes the conventional
    /// <c>response.ok</c> check and only fails later, on parsing. Callers that are not navigating are
    /// refused with a status instead, so the refusal is visible where it is checked.
    /// <para>
    /// <see cref="FetchDestinationHeader"/> decides when it is present, because it is the only signal that
    /// separates a document navigation from a scripted request issued by the very same browser —
    /// <c>fetch()</c> sends <c>Accept: *&#47;*</c>, which reads as "HTML will do" and is exactly the
    /// misclassification to avoid. Only when the header is absent — a client predating fetch metadata —
    /// does <c>Accept</c> decide, and then nothing short of an explicit <c>text/html</c> counts, so a
    /// caller that states nothing is treated as the API caller it almost always is.
    /// </para>
    /// </remarks>
    public static bool IsDocumentNavigation(this HttpContext context)
    {
        var destination = context.Request.Headers[FetchDestinationHeader].ToString();

        if (!string.IsNullOrEmpty(destination))
        {
            return string.Equals(destination, "document", StringComparison.OrdinalIgnoreCase)
                || string.Equals(destination, "iframe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(destination, "frame", StringComparison.OrdinalIgnoreCase);
        }

        return MediaTypeHeaderValue.TryParseList(context.Request.Headers.Accept, out var accepted)
            && accepted.Any(AcceptsHtml);
    }

    /// <summary>
    /// Determines whether the request targets any authentication bootstrap endpoint.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is part of authentication bootstrap; otherwise <see langword="false"/>.</returns>
    public static bool IsAuthenticationBootstrap(this HttpContext context) =>
        context.IsAuthenticationUI() || (context.Request.Path.Value?.StartsWith(SignInPathPrefix, StringComparison.OrdinalIgnoreCase) ?? false);

    /// <summary>
    /// Attempts to extract the invitation token from the current invitation request path.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <param name="invitationToken">The extracted invitation token when present.</param>
    /// <returns><see langword="true"/> if an invitation token was extracted; otherwise <see langword="false"/>.</returns>
    public static bool TryGetInvitationToken(this HttpContext context, out string invitationToken)
    {
        invitationToken = string.Empty;

        if (!context.Request.Path.StartsWithSegments(WellKnownPaths.InvitePathPrefix, out var remaining))
        {
            return false;
        }

        invitationToken = remaining.Value?.TrimStart('/') ?? string.Empty;

        return true;
    }

    /// <summary>
    /// Attempts to get the pending invitation token from the request cookies.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <param name="invitationToken">The pending invitation token when present.</param>
    /// <returns><see langword="true"/> if a pending invitation token exists; otherwise <see langword="false"/>.</returns>
    public static bool TryGetPendingInvitationToken(this HttpContext context, out string invitationToken)
    {
        invitationToken = string.Empty;

        if (!context.Request.Cookies.TryGetValue(Cookies.InviteToken, out var token)
            || string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        invitationToken = token;

        return true;
    }

    /// <summary>
    /// Determines whether an <c>Accept</c> entry asks for HTML.
    /// </summary>
    /// <param name="mediaType">The parsed <c>Accept</c> entry.</param>
    /// <returns><see langword="true"/> when the entry asks for HTML; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Only an explicit <c>text/html</c> counts. The wildcards <c>*&#47;*</c> and <c>text/*</c> do not:
    /// they are what a client sends when it will take whatever it is given, and reading them as a request
    /// for a page is the misclassification that turns a refusal into a recorded success. A quality of zero
    /// is the caller stating outright that HTML is unacceptable, so it is honored rather than matched.
    /// </remarks>
    static bool AcceptsHtml(MediaTypeHeaderValue mediaType) =>
        string.Equals(mediaType.MediaType.Value, HtmlMediaType, StringComparison.OrdinalIgnoreCase)
        && mediaType.Quality != 0;
}