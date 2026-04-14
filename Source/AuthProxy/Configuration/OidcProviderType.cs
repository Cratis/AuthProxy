// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the type / brand of an OIDC provider, used by the login page to pick the correct logo.
/// </summary>
public enum OidcProviderType
{
    /// <summary>A generic / unknown provider.</summary>
    Custom = 0,

    /// <summary>Microsoft identity platform (Azure AD / Entra ID).</summary>
    Microsoft = 1,

    /// <summary>Google identity.</summary>
    Google = 2,

    /// <summary>GitHub OAuth / OIDC.</summary>
    GitHub = 3,

    /// <summary>Apple Sign-In.</summary>
    Apple = 4
}
