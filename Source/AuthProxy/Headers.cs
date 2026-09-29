// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Represents all the HTTP headers used by the ingress.
/// </summary>
public static class Headers
{
    /// <summary>
    /// Microsoft Identity Platform client principal (base64 encoded JSON).
    /// </summary>
    public const string Principal = "x-ms-client-principal";

    /// <summary>
    /// Microsoft Identity Platform client principal ID.
    /// </summary>
    public const string PrincipalId = "x-ms-client-principal-id";

    /// <summary>
    /// Microsoft Identity Platform client principal name.
    /// </summary>
    public const string PrincipalName = "x-ms-client-principal-name";

    /// <summary>
    /// The RFC 8187 <c language="text">ext-value</c> form of the client principal name, sent alongside
    /// <see cref="PrincipalName"/> only when the name could not travel as US-ASCII.
    /// </summary>
    /// <remarks>
    /// The starred sibling is the established HTTP idiom for exactly this — <c language="text">Content-Disposition</c>
    /// pairs <c language="text">filename</c> with <c language="text">filename*</c> (RFC 6266 §4.3). Its presence is what tells a consumer
    /// that <see cref="PrincipalName"/> carries an encoded value rather than a literal one; its absence
    /// means the plain header is the name verbatim. The exact, unencoded value is always available in
    /// <see cref="Principal"/> as <c language="text">userDetails</c>, which remains the canonical source.
    /// </remarks>
    public const string PrincipalNameExtended = "x-ms-client-principal-name*";

    /// <summary>
    /// Cratis tenant identifier.
    /// </summary>
    public const string TenantId = "Tenant-ID";

    /// <summary>
    /// The client an access token was issued to — its <c language="text">azp</c>, or failing that its
    /// <c language="text">client_id</c> — sent only for a request authenticated on a bearer route.
    /// </summary>
    /// <remarks>
    /// This is the client's asserted identity: a public client cannot prove which program is using it.
    /// </remarks>
    public const string TokenClientId = "x-cratis-token-client-id";

    /// <summary>
    /// The space-separated scopes granted to an access token, sent only for a request authenticated on a bearer
    /// route.
    /// </summary>
    public const string TokenScope = "x-cratis-token-scope";

    /// <summary>
    /// Service identifier used to route requests to the appropriate service.
    /// </summary>
    public const string ServiceId = "Service-ID";
}
