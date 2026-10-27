// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents the body of the session-started notification.
/// </summary>
/// <param name="SessionId">The session identifier.</param>
/// <param name="Tenant">The tenant the session acts in.</param>
/// <param name="Issue">The issue the grant was given for.</param>
/// <param name="Subject">The represented user's subject.</param>
/// <param name="Actor">The support person or agent acting.</param>
/// <param name="StartedAt">When the session started.</param>
/// <param name="ExpiresAt">When the session ends at the latest.</param>
/// <param name="GrantValidUntil">The <c language="text">validUntil</c> the grant check stated.</param>
public sealed record OnBehalfSessionStartedNotification(
    [property: JsonPropertyName("sessionId")] string SessionId,
    [property: JsonPropertyName("tenant")] string Tenant,
    [property: JsonPropertyName("issue")] string Issue,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("actor")] OnBehalfActorNotification Actor,
    [property: JsonPropertyName("startedAt")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("expiresAt")] DateTimeOffset ExpiresAt,
    [property: JsonPropertyName("grantValidUntil")] DateTimeOffset GrantValidUntil);
