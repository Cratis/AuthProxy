// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Resolves the OIDC end-session endpoint (RP-initiated logout URL) for the provider a session was
/// established with.
/// </summary>
public interface IEndSessionEndpointResolver
{
    /// <summary>
    /// Resolves the end-session endpoint for the authentication scheme that established the current session.
    /// </summary>
    /// <param name="scheme">The authentication scheme name the user signed in with, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">A token to cancel the discovery lookup.</param>
    /// <returns>
    /// The absolute end-session endpoint URL when the scheme is an OIDC provider whose discovery document
    /// advertises one; otherwise <see langword="null"/>. OAuth 2.0 providers (which have no standard OIDC
    /// end-session endpoint), unknown schemes, and discovery failures all resolve to <see langword="null"/>
    /// so the caller can fall back to a local-only logout.
    /// </returns>
    Task<string?> Resolve(string? scheme, CancellationToken cancellationToken);
}
