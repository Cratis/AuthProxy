// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Represents well-known cookie names used by the ingress.
/// </summary>
public static class Cookies
{
    /// <summary>
    /// Cookie holding the enriched identity details from the application's identity provider endpoint.
    /// </summary>
    public const string Identity = ".cratis-identity";

    /// <summary>
    /// Short-lived HTTP-only cookie used to carry the invite token across the OIDC redirect.
    /// </summary>
    public const string InviteToken = ".cratis-invite";

    /// <summary>
    /// Short-lived HTTP-only cookie used to carry an in-flight registration across the OIDC redirect.
    /// </summary>
    public const string Registration = ".cratis-registration";

    /// <summary>
    /// Short-lived cookie injected by the proxy when serving the invitation provider-selection page.
    /// Contains a JSON array of <c>OidcProviderInfo</c> objects so the page can render
    /// per-provider sign-in links without a separate HTTP round-trip.
    /// This cookie is intentionally <em>not</em> HTTP-only so that client-side script can read it.
    /// </summary>
    public const string Providers = ".cratis-providers";

    /// <summary>
    /// Short-lived cookie injected by the proxy when serving the tenant-selection page.
    /// Contains a JSON array of tenant options (<c>id</c> and <c>name</c>) so the page can render
    /// without calling the tenant endpoint directly.
    /// This cookie is intentionally <em>not</em> HTTP-only so that client-side script can read it.
    /// </summary>
    public const string Tenants = ".cratis-tenants";

    /// <summary>
    /// Cookie that stores the selected tenant identifier for subsequent requests.
    /// </summary>
    public const string Tenant = ".cratis-tenant";

    /// <summary>
    /// Short-lived HTTP-only cookie used to carry the validated final post-logout redirect target across
    /// the RP-initiated logout round-trip to the identity provider's end-session endpoint and back to the
    /// logout callback (<see cref="WellKnownPaths.LogoutCallback"/>).
    /// </summary>
    public const string LogoutRedirect = ".cratis-logout";

    /// <summary>
    /// Name prefix of the transient correlation cookie the ASP.NET Core OAuth/OIDC middleware writes for
    /// every sign-in handshake. Each carries a random per-attempt suffix, so an abandoned handshake leaves
    /// one behind; they are cleared on logout by matching this prefix.
    /// </summary>
    public const string CorrelationPrefix = ".AspNetCore.Correlation.";

    /// <summary>
    /// Name prefix of the transient nonce cookie the ASP.NET Core OpenID Connect middleware writes for every
    /// sign-in handshake. Like <see cref="CorrelationPrefix"/> it carries a random suffix and is cleared on
    /// logout by matching this prefix.
    /// </summary>
    public const string NoncePrefix = ".AspNetCore.OpenIdConnect.Nonce.";
}
