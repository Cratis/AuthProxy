// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Defines the claim types AuthProxy writes into the forwarded principal of a request authenticated on a bearer
/// route.
/// </summary>
/// <remarks>
/// The whole <c language="text">urn:cratis:bearer:</c> namespace is AuthProxy's own. It is removed from every token before
/// AuthProxy writes its values, and removed from every principal that was not authenticated on a bearer route, so
/// a backend can rely on these claims meaning exactly what is documented here and on their presence meaning the
/// request came through a bearer route.
/// </remarks>
public static class BearerRouteClaims
{
    /// <summary>
    /// The claim type for the validated issuer of the access token.
    /// </summary>
    public const string Issuer = "urn:cratis:bearer:issuer";

    /// <summary>
    /// The claim type for the access token's own <c language="text">sub</c>, kept even when a claim mapping rewrites
    /// <c language="text">sub</c> for the backend.
    /// </summary>
    public const string Subject = "urn:cratis:bearer:subject";

    /// <summary>
    /// The claim type for the client the token was issued to, from <c language="text">azp</c> or, failing that,
    /// <c language="text">client_id</c>. This is the client's asserted identity: a public client cannot prove which program
    /// is using it.
    /// </summary>
    public const string ClientId = "urn:cratis:bearer:client-id";

    /// <summary>
    /// The claim type for a granted scope. One claim per scope.
    /// </summary>
    public const string Scope = "urn:cratis:bearer:scope";

    const string ReservedPrefix = "urn:cratis:bearer:";

    /// <summary>
    /// Determines whether a claim type belongs to the namespace AuthProxy reserves for bearer-route metadata.
    /// </summary>
    /// <param name="claimType">The claim type to inspect.</param>
    /// <returns><see langword="true"/> when the claim type is reserved; otherwise <see langword="false"/>.</returns>
    public static bool IsReserved(string claimType) => claimType.StartsWith(ReservedPrefix, StringComparison.OrdinalIgnoreCase);
}
