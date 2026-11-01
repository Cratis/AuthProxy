// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// The kinds of identity provider a Screenplay model can name.
/// </summary>
public enum ProviderKind
{
    /// <summary>No provider kind.</summary>
    None = 0,

    /// <summary>Microsoft Entra ID.</summary>
    EntraId = 1,

    /// <summary>GitHub, an OAuth 2.0 provider.</summary>
    GitHub = 2,

    /// <summary>Google.</summary>
    Google = 3,

    /// <summary>Sign in with Apple.</summary>
    Apple = 4,

    /// <summary>Any OpenID Connect provider.</summary>
    OpenId = 5
}
