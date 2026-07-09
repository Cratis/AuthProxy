// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The well-known payload sent to a downstream verification endpoint.
/// </summary>
/// <param name="Service">The target service key.</param>
/// <param name="RoutePrefix">The route prefix the issued token should be scoped to.</param>
/// <param name="ClientId">The client identifier to verify.</param>
/// <param name="ClientSecret">The client secret to verify.</param>
public record ClientCredentialsVerificationRequest(
    string Service,
    string RoutePrefix,
    string ClientId,
    string ClientSecret);
