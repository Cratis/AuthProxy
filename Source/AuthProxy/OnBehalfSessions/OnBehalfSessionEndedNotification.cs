// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents the body of the session-ended notification.
/// </summary>
/// <param name="SessionId">The session identifier.</param>
/// <param name="Tenant">The tenant the session acted in.</param>
/// <param name="Issue">The issue the grant was given for.</param>
/// <param name="Subject">The represented user's subject.</param>
/// <param name="Actor">The support person or agent who acted.</param>
/// <param name="StartedAt">When the session started.</param>
/// <param name="EndedAt">When the session ended.</param>
/// <param name="Reason">Why the session ended; see <see cref="OnBehalfSessionEndReasons.ToWireValue"/>.</param>
public sealed record OnBehalfSessionEndedNotification(
    [property: JsonPropertyName("sessionId")] string SessionId,
    [property: JsonPropertyName("tenant")] string Tenant,
    [property: JsonPropertyName("issue")] string Issue,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("actor")] OnBehalfActorNotification Actor,
    [property: JsonPropertyName("startedAt")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("endedAt")] DateTimeOffset EndedAt,
    [property: JsonPropertyName("reason")] string Reason);
