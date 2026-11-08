// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Introspection;

/// <summary>
/// Represents what an issuer's introspection endpoint said about an access token.
/// </summary>
public enum IntrospectionVerdict
{
    /// <summary>The endpoint answered that the token is active, and the answer is consistent with the validated token.</summary>
    Active = 0,

    /// <summary>The endpoint answered that the token is not active, or its answer contradicts the validated token.</summary>
    Inactive = 1,

    /// <summary>The endpoint could not be asked or its answer could not be understood.</summary>
    Unavailable = 2,
}
