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
    /// The OAuth 2.0 grant type supported by the token endpoint.
    /// </summary>
    public const string GrantType = "client_credentials";

    /// <summary>
    /// The claim type that stores the target service key.
    /// </summary>
    public const string ServiceClaimType = "cratis/service";

    /// <summary>
    /// The claim type that stores the route prefix the token is scoped to.
    /// </summary>
    public const string RoutePrefixClaimType = "cratis/route-prefix";
}
