// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Represents the outcome of validating the access token on a bearer route.
/// </summary>
public enum BearerTokenValidationStatus
{
    /// <summary>The token is valid for the route and carries a tenant.</summary>
    Succeeded = 0,

    /// <summary>The request carries no bearer token.</summary>
    Missing = 1,

    /// <summary>The token is malformed, expired, wrongly signed, from another issuer or for another audience.</summary>
    Invalid = 2,

    /// <summary>The token is valid but lacks a scope the route requires.</summary>
    InsufficientScope = 3,

    /// <summary>The token is valid but carries no single usable tenant.</summary>
    MissingTenant = 4,

    /// <summary>The issuer's metadata or signing keys could not be retrieved, so the token could not be checked.</summary>
    IssuerUnavailable = 5,
}
