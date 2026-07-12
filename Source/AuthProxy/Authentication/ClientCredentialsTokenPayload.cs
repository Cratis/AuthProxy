// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The protected contents of an AuthProxy-issued bearer token.
/// </summary>
/// <param name="Service">The service the token is scoped to.</param>
/// <param name="RoutePrefix">The route prefix the token is scoped to.</param>
/// <param name="ClientId">The verified client identifier.</param>
/// <param name="Tenant">The tenant resolved from the downstream verification response, when one was returned.</param>
public record ClientCredentialsTokenPayload(
    string Service,
    string RoutePrefix,
    string ClientId,
    string? Tenant = null);
