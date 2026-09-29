// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Defines a source of the signing keys a bearer-token issuer publishes.
/// </summary>
public interface IBearerIssuerMetadata
{
    /// <summary>
    /// Gets the issuer's current signing keys, from its metadata document and JWKS.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="cancellationToken">The request's cancellation token.</param>
    /// <returns>The signing keys, or <see langword="null"/> when they could not be retrieved or the metadata names another issuer.</returns>
    Task<IReadOnlyCollection<SecurityKey>?> GetSigningKeys(ResolvedBearerIssuer issuer, CancellationToken cancellationToken);

    /// <summary>
    /// Asks for the issuer's metadata and keys to be retrieved again, because a token names a key that is not known.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <remarks>
    /// Refreshes are rate limited, so a flood of tokens naming unknown keys cannot turn into a flood of requests to
    /// the issuer.
    /// </remarks>
    void RequestRefresh(ResolvedBearerIssuer issuer);
}
