// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents one on-behalf session: who is acting, on behalf of whom, in which tenant, for which issue, and for
/// how long at most.
/// </summary>
/// <param name="SessionId">The random identifier AuthProxy issued for the session.</param>
/// <param name="Actor">The support person or agent acting.</param>
/// <param name="Tenant">The tenant the session acts in.</param>
/// <param name="Subject">The subject (<c language="text">userId</c>) of the represented user.</param>
/// <param name="Issue">The issue the grant was given for.</param>
/// <param name="StartedAt">When the session started.</param>
/// <param name="ExpiresAt">When the session ends at the latest, whatever the grant says.</param>
/// <remarks>
/// This is what the session cookie carries, protected. It deliberately holds nothing about the represented user
/// beyond the subject the actor asked for: their identity details come from the application's grant check on
/// every re-check, never from the browser.
/// </remarks>
public sealed record OnBehalfSession(
    string SessionId,
    OnBehalfActor Actor,
    string Tenant,
    string Subject,
    string Issue,
    DateTimeOffset StartedAt,
    DateTimeOffset ExpiresAt);
