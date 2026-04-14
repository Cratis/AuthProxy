// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress;

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
    /// The well-known path for the login selection page served by the Web project.
    /// Unauthenticated users are redirected here when multiple providers are configured.
    /// </summary>
    public const string LoginPage = "/.cratis/select-provider";

    /// <summary>
    /// The well-known path prefix that triggers invite-token handling.
    /// Append the token to complete the URL (e.g. <c>/invite/&lt;token&gt;</c>).
    /// </summary>
    public const string InvitePathPrefix = "/invite";
}

