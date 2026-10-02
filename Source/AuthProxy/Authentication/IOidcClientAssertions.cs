// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Defines a system that creates the <c language="text">client_assertion</c> an OIDC provider authenticates AuthProxy with.
/// </summary>
public interface IOidcClientAssertions
{
    /// <summary>
    /// Creates a client assertion for one request to the provider.
    /// </summary>
    /// <param name="scheme">The authentication scheme of the provider; the loaded credential is kept per scheme.</param>
    /// <param name="provider">The provider registration. Its client credential must use a client assertion.</param>
    /// <param name="audience">The endpoint the assertion is presented to, normally the provider's token endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>The serialized client assertion.</returns>
    /// <exception cref="OidcClientCredentialUnavailable">The credential could not be loaded or produced no assertion.</exception>
    Task<string> Create(string scheme, C.OidcProvider provider, string audience, CancellationToken cancellationToken);
}
