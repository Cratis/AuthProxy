// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// The claim names and values of the tokens AuthProxy signs for on-behalf sessions. These are the wire contract an
/// application verifies against.
/// </summary>
/// <remarks>
/// Every token also carries the registered <c language="text">iss</c>, <c language="text">aud</c>, <c language="text">iat</c>,
/// <c language="text">nbf</c>, <c language="text">exp</c> and a random <c language="text">jti</c>, and names its signing key in the
/// <c language="text">kid</c> header. <see cref="Subject"/> is the represented user and <see cref="Actor"/> is the RFC 8693
/// actor claim naming who is really acting.
/// </remarks>
public static class OnBehalfAttestationClaims
{
    /// <summary>
    /// The claim naming what the token is for. A verifier must check it, so a token issued for one call can never be
    /// presented as another.
    /// </summary>
    public const string Purpose = "purpose";

    /// <summary>
    /// The <see cref="Purpose"/> of the token on a grant check.
    /// </summary>
    public const string GrantCheckPurpose = "on-behalf-grant-check";

    /// <summary>
    /// The <see cref="Purpose"/> of the token on the session-started notification.
    /// </summary>
    public const string SessionStartedPurpose = "on-behalf-session-started";

    /// <summary>
    /// The <see cref="Purpose"/> of the token on the session-ended notification.
    /// </summary>
    public const string SessionEndedPurpose = "on-behalf-session-ended";

    /// <summary>
    /// The <see cref="Purpose"/> of the token forwarded with every on-behalf request.
    /// </summary>
    public const string ForwardPurpose = "on-behalf-forward";

    /// <summary>
    /// The HTTP method of the call the token accompanies (RFC 9449 <c language="text">htm</c>).
    /// </summary>
    public const string HttpMethod = "htm";

    /// <summary>
    /// The scheme, authority and path of the call the token accompanies, without query or fragment
    /// (RFC 9449 <c language="text">htu</c>).
    /// </summary>
    public const string HttpUri = "htu";

    /// <summary>
    /// The base64url SHA-256 digest of the exact body bytes of the call the token accompanies. A call without a body
    /// digests the empty body.
    /// </summary>
    public const string BodyHash = "body_hash";

    /// <summary>
    /// The subject of the represented user.
    /// </summary>
    public const string Subject = "sub";

    /// <summary>
    /// The RFC 8693 actor claim: an object naming the support person or agent actually acting, with
    /// <see cref="ActorSubject"/> and <see cref="ActorIdentityProvider"/>.
    /// </summary>
    public const string Actor = "act";

    /// <summary>
    /// The actor's subject, inside <see cref="Actor"/>.
    /// </summary>
    public const string ActorSubject = "sub";

    /// <summary>
    /// The actor's identity provider, inside <see cref="Actor"/>.
    /// </summary>
    public const string ActorIdentityProvider = "idp";

    /// <summary>
    /// The tenant the session acts in.
    /// </summary>
    public const string Tenant = "tenant";

    /// <summary>
    /// The issue the grant was given for.
    /// </summary>
    public const string Issue = "issue";

    /// <summary>
    /// The on-behalf session identifier.
    /// </summary>
    public const string SessionId = "sid";

    /// <summary>
    /// On a forwarded request: the base64url SHA-256 digest of the exact <c language="text">x-ms-client-principal</c> header value.
    /// </summary>
    public const string PrincipalHash = "principal_hash";

    /// <summary>
    /// On a forwarded request: the base64url SHA-256 digest of the exact <c language="text">x-cratis-on-behalf-actor</c> header value.
    /// </summary>
    public const string ActorHash = "actor_hash";
}
