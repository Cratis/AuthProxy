// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents what an actor asked to start.
/// </summary>
/// <param name="Tenant">The tenant to act in.</param>
/// <param name="Subject">The subject of the user to represent.</param>
/// <param name="Issue">The issue the grant was given for.</param>
public sealed record OnBehalfStartRequest(
    [property: JsonPropertyName("tenant")] string? Tenant,
    [property: JsonPropertyName("subject")] string? Subject,
    [property: JsonPropertyName("issue")] string? Issue);
