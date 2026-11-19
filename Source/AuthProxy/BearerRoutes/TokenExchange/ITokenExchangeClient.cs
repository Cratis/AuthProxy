// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.TokenExchange;

/// <summary>Asks the configured Identity authority for a tenant-bound access token.</summary>
public interface ITokenExchangeClient
{
    /// <summary>Exchanges a subject token using only trusted configuration and an independently verified target.</summary>
    /// <param name="configuration">The operator's exchange configuration.</param>
    /// <param name="issuer">The configured external issuer.</param>
    /// <param name="token">The subject token, never logged.</param>
    /// <param name="tenant">The verified addressed tenant.</param>
    /// <param name="cancellationToken">The request's abort signal.</param>
    /// <returns>The exchange outcome, still requiring signature validation.</returns>
    Task<TokenExchangeResult> Exchange(C.BearerTokenExchange configuration, C.BearerTokenExchangeIssuer issuer, string token, string tenant, CancellationToken cancellationToken);
}
