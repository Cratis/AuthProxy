// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.TokenExchange;

/// <summary>The deliberately limited outcomes exposed by Identity exchange.</summary>
public enum TokenExchangeVerdict
{
    /// <summary>No credential was obtained.</summary>
    Refused = 0,

    /// <summary>A credential was obtained; it still requires normal JWT validation.</summary>
    Success = 1,

    /// <summary>The authority could not complete the request.</summary>
    Unavailable = 2,
}
