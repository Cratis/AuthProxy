// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Represents well-known URL paths used by the ingress.
/// </summary>
public static class WellKnownPaths
{
    /// <summary>
    /// The well-known path for the Cratis identity details endpoint on a microservice.
    /// </summary>
    public const string IdentityDetails = "/.cratis/me";

    /// <summary>
    /// The well-known path for the OIDC providers endpoint.
    /// Returns a JSON array of <c>OidcProviderInfo</c> objects.
    /// </summary>
    public const string Providers = "/.cratis/providers";

    /// <summary>
    /// The well-known path prefix for initiating a login flow for a specific provider.
    /// Append the scheme name to complete the URL (e.g. <c>/.cratis/login/microsoft</c>).
    /// </summary>
    public const string LoginPrefix = "/.cratis/login";

    /// <summary>
    /// The well-known token endpoint for the back-channel client-credentials flow.
    /// </summary>
    public const string Token = "/.cratis/token";

    /// <summary>
    /// The well-known path for the login selection page served by the Web project.
    /// Unauthenticated users are redirected here when multiple providers are configured.
    /// </summary>
    public const string LoginPage = "/.cratis/select-provider";

    /// <summary>
    /// The well-known path used by the tenant-selection page to submit the chosen tenant.
    /// </summary>
    public const string SelectTenant = "/.cratis/select-tenant";

    /// <summary>
    /// The well-known path that logs the current user out. It initiates a full-chain logout: when the
    /// session was established through an OIDC provider it redirects the browser to that provider's
    /// end-session endpoint (RP-initiated logout), otherwise it clears the local session directly. The
    /// final destination is supplied in the <c>redirect</c> query-string parameter.
    /// </summary>
    public const string Logout = "/.cratis/logout";

    /// <summary>
    /// The well-known path the identity provider redirects back to after an RP-initiated logout completes.
    /// It clears every AuthProxy-generated cookie and redirects to the validated final <c>redirect</c>
    /// target that was carried across the round-trip. Must be a segment under <see cref="Logout"/> so the
    /// logout middleware can distinguish it from the initiation request.
    /// </summary>
    public const string LogoutCallback = "/.cratis/logout/callback";

    /// <summary>
    /// The well-known path prefix for initiating a session-preserving link flow for a specific provider.
    /// Append the scheme name to complete the URL (e.g. <c>/.cratis/link/github</c>).
    /// Unlike <see cref="LoginPrefix"/>, the link flow authenticates a second provider identity for the
    /// already signed-in user <em>without</em> replacing the primary authentication cookie/session.
    /// </summary>
    public const string Link = "/.cratis/link";

    /// <summary>
    /// The well-known path prefix that triggers invite-token handling.
    /// Append the token to complete the URL (e.g. <c>/invite/&lt;token&gt;</c>).
    /// </summary>
    public const string InvitePathPrefix = "/invite";

    /// <summary>
    /// The well-known path that triggers the registration flow.
    /// </summary>
    public const string Registration = "/register";

    /// <summary>
    /// The request path prefix under which custom pages (error pages, login UI, etc.) are served as static files.
    /// All requests under this prefix are always allowed anonymously.
    /// </summary>
    public const string Pages = "/_pages";
}
