// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Defines the server-side store of users' refresh tokens and the access tokens obtained with them.
/// </summary>
/// <remarks>
/// Entries are keyed by an unguessable session identifier that only the encrypted session cookie carries, so the
/// tokens themselves never reach the browser.
/// </remarks>
public interface IUserTokenStore
{
    /// <summary>
    /// Stores a new session and returns its identifier.
    /// </summary>
    /// <param name="session">The session to store.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>The identifier to keep in the session cookie.</returns>
    Task<string> Create(UserTokenSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Gets a session.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>The session, or <see langword="null"/> when it is unknown or has expired.</returns>
    Task<UserTokenSession?> Get(string sessionId, CancellationToken cancellationToken);

    /// <summary>
    /// Replaces a session, for example after the provider rotated the refresh token.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    Task Update(string sessionId, UserTokenSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Removes a session and every access token obtained for it.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    Task Remove(string sessionId, CancellationToken cancellationToken);

    /// <summary>
    /// Gets a cached access token for a session and audience.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="audience">The audience key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>The cached token, or <see langword="null"/> when there is none.</returns>
    Task<CachedUserAccessToken?> GetAccessToken(string sessionId, string audience, CancellationToken cancellationToken);

    /// <summary>
    /// Caches an access token for a session and audience until it is due for renewal.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="audience">The audience key.</param>
    /// <param name="token">The token.</param>
    /// <param name="renewAt">When the token must no longer be handed out.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    Task SetAccessToken(string sessionId, string audience, CachedUserAccessToken token, DateTimeOffset renewAt, CancellationToken cancellationToken);
}
