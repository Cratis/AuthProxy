// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Defines something that adds provider-specific claims to an identity while a sign-in is being completed.
/// </summary>
/// <remarks>
/// An OAuth 2.0 provider's user-information endpoint returns a profile, and
/// <see cref="C.OAuthProvider.ClaimMappings"/> turns fields of that profile into claims. Anything the
/// provider keeps behind a <em>different</em> endpoint — GitHub's organization and team membership is the
/// case that motivated this — has no field to map, so it needs fetching before the ticket is signed in.
/// <para>
/// Doing it here rather than in a provider-specific authorization rule keeps one authorization mechanism
/// instead of two: what arrives is an ordinary claim, so the generic claim requirements gate on it, and
/// the application behind the proxy receives it on the forwarded principal like every other claim.
/// </para>
/// </remarks>
public interface IProviderClaimsEnricher
{
    /// <summary>
    /// Determines whether this enricher has anything to contribute for a provider.
    /// </summary>
    /// <param name="provider">The OAuth provider completing a sign-in.</param>
    /// <returns><see langword="true"/> when it applies to the provider; otherwise <see langword="false"/>.</returns>
    bool CanEnrich(C.OAuthProvider provider);

    /// <summary>
    /// Adds claims to the identity being signed in.
    /// </summary>
    /// <param name="identity">The identity to add claims to.</param>
    /// <param name="provider">The OAuth provider completing the sign-in.</param>
    /// <param name="backchannel">The provider handler's HTTP client, already configured for the provider.</param>
    /// <param name="accessToken">The access token issued for the signing-in user.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <remarks>
    /// An implementation must never throw. It runs inside the sign-in handshake, so a failure here would
    /// surface to the user as a broken login rather than as the missing claims it actually is — and the
    /// missing claims already fail closed, because a requirement naming a claim that was never added is
    /// not satisfied.
    /// </remarks>
    Task Enrich(ClaimsIdentity identity, C.OAuthProvider provider, HttpClient backchannel, string accessToken, CancellationToken cancellationToken);
}
