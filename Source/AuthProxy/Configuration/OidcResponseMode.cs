// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Defines how an OIDC provider returns the authorization code to the callback endpoint.
/// </summary>
public enum OidcResponseMode
{
    /// <summary>
    /// The code comes back in the query string of a top-level GET redirect. This is the default: the
    /// handshake's SameSite=Lax correlation and nonce cookies accompany a top-level GET, so the callback
    /// can always complete without weakening the cookies.
    /// </summary>
    Query = 0,

    /// <summary>
    /// The code comes back in the body of a cross-site form POST. Browsers do not attach SameSite=Lax
    /// cookies to a cross-site POST, so choosing this switches the provider's handshake cookies to
    /// SameSite=None + Secure. Reserve it for providers that mandate form_post, such as Apple when the
    /// name or email scopes are requested.
    /// </summary>
    FormPost = 1,
}
