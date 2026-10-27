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
    /// The prefix shared by every Microsoft Identity Platform client principal header, including ones this
    /// proxy never writes, such as <c language="text">x-ms-client-principal-idp</c>.
    /// </summary>
    /// <remarks>
    /// A caller must not be able to hand a backend any header that begins with this, so inbound headers are
    /// matched by prefix rather than against the short list of names the proxy itself writes.
    /// </remarks>
    public const string PrincipalPrefix = "x-ms-client-principal";

    /// <summary>
    /// Cratis tenant identifier, the tenant AuthProxy resolved for the request.
    /// </summary>
    /// <remarks>
    /// This is the name Arc resolves the tenant from by default, so an Arc application behind AuthProxy needs
    /// no tenancy configuration to read it. The same value is also forwarded in <see cref="LegacyTenantId"/>.
    /// </remarks>
    public const string TenantId = "x-cratis-tenant-id";

    /// <summary>
    /// The legacy tenant header, forwarded alongside <see cref="TenantId"/> during the transition.
    /// </summary>
    /// <remarks>
    /// Forwarding this name is deprecated and will be removed in a future major release. Both inbound
    /// tenant headers are stripped before the resolved tenant is written back.
    /// </remarks>
    public const string LegacyTenantId = "Tenant-ID";

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
    /// The prefix shared by every on-behalf header. Only AuthProxy writes these, so every inbound header beginning
    /// with it is removed before anything is forwarded.
    /// </summary>
    public const string OnBehalfPrefix = "x-cratis-on-behalf";

    /// <summary>
    /// The actor of an on-behalf session — the support person or agent actually acting — as a client principal,
    /// encoded exactly like <see cref="Principal"/> (base64 of the Microsoft client principal JSON). Sent only during
    /// an on-behalf session, in which <see cref="Principal"/> carries the represented user.
    /// </summary>
    public const string OnBehalfActor = "x-cratis-on-behalf-actor";

    /// <summary>
    /// The signed assertion (an RS256 JSON Web Token) binding <see cref="Principal"/>, <see cref="OnBehalfActor"/>,
    /// the tenant, the session and the issue together. Sent with every on-behalf request; a backend must verify it
    /// before believing either identity header.
    /// </summary>
    public const string OnBehalfAssertion = "x-cratis-on-behalf-assertion";

    /// <summary>
    /// The response header naming why an on-behalf session ended, sent on the response that refuses the request it
    /// ended on.
    /// </summary>
    public const string OnBehalfEnded = "x-cratis-on-behalf-ended";

    /// <summary>
    /// The response header naming why AuthProxy refused a request during an on-behalf session that is still active,
    /// for instance <c language="text">service-not-permitted</c> for a request routed to a service the session may not
    /// reach. Unlike <see cref="OnBehalfEnded"/>, the session goes on.
    /// </summary>
    public const string OnBehalfRefused = "x-cratis-on-behalf-refused";

    /// <summary>
    /// Service identifier used to route requests to the appropriate service.
    /// </summary>
    /// <remarks>
    /// This is the name Arc's frontend sends by default when a microservice is set. The selected identifier
    /// is forwarded under this name and <see cref="LegacyServiceId"/>.
    /// </remarks>
    public const string ServiceId = "x-cratis-microservice";

    /// <summary>
    /// The service header earlier releases routed on. It is still accepted inbound and means the same as
    /// <see cref="ServiceId"/>; <see cref="ServiceId"/> wins when both are sent. Forwarding the legacy name is
    /// deprecated and will be removed in a future major release.
    /// </summary>
    public const string LegacyServiceId = "Service-ID";
}
