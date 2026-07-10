// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Defines constants used by the back-channel client-credentials flow.
/// </summary>
public static class ClientCredentialsDefaults
{
    /// <summary>
    /// The composite authentication scheme that selects between cookies and bearer tokens.
    /// </summary>
    public const string CompositeAuthenticationScheme = "AuthProxyAuthentication";

    /// <summary>
    /// The authentication scheme used for AuthProxy-issued bearer tokens.
    /// </summary>
    public const string AuthenticationScheme = "AuthProxyClientCredentials";

    /// <summary>
    /// The OAuth 2.0 grant type used to request a token with client credentials.
    /// </summary>
    public const string GrantType = "client_credentials";

    /// <summary>
    /// The OAuth 2.0 grant type used to exchange a refresh token for a new access token.
    /// </summary>
    public const string RefreshGrantType = "refresh_token";

    /// <summary>
    /// The claim type that stores the target service key.
    /// </summary>
    public const string ServiceClaimType = "cratis/service";

    /// <summary>
    /// The claim type that stores the route prefix the token is scoped to.
    /// </summary>
    public const string RoutePrefixClaimType = "cratis/route-prefix";

    /// <summary>
    /// The claim type that stores the tenant resolved from the downstream verification response.
    /// Configure a <c>Claim</c> tenant resolution strategy with this claim type to have AuthProxy
    /// resolve the tenant for client-credentials-authenticated requests.
    /// </summary>
    public const string TenantClaimType = "cratis/tenant";

    /// <summary>
    /// The <see cref="HttpContext.Items"/> key under which the composite scheme selector stashes an
    /// already-validated <see cref="ClientCredentialsTokenPayload"/>, so the bearer authentication handler
    /// does not have to unprotect the same token a second time.
    /// </summary>
    internal const string ValidatedTokenPayloadItemKey = "Cratis.AuthProxy.ClientCredentials.ValidatedPayload";
}
