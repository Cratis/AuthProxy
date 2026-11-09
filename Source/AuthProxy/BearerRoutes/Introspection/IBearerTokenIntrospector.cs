// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Introspection;

/// <summary>
/// Defines asking a token's issuer whether an access token that passed local validation is still active.
/// </summary>
public interface IBearerTokenIntrospector
{
    /// <summary>
    /// Asks the issuer whether the token is still active.
    /// </summary>
    /// <param name="token">The access token, already validated locally.</param>
    /// <param name="validated">The result of validating <paramref name="token"/>.</param>
    /// <param name="issuer">The issuer, which has introspection configured.</param>
    /// <param name="cancellationToken">The request's cancellation token.</param>
    /// <returns>The verdict. Never throws for an endpoint failure; that is <see cref="IntrospectionVerdict.Unavailable"/>.</returns>
    Task<IntrospectionVerdict> Introspect(string token, BearerTokenValidation validated, ResolvedBearerIssuer issuer, CancellationToken cancellationToken);
}
