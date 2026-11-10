// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Describes one call to a service's identity endpoint.
/// </summary>
/// <param name="ServiceName">The configured name of the service being called.</param>
/// <param name="BaseUrl">The service's backend base URL.</param>
/// <param name="Principal">The enriched principal to present to the service.</param>
/// <param name="TenantId">The tenant the caller is acting in.</param>
/// <param name="LogIdentifier">The non-identifying label used when logging about this caller.</param>
/// <param name="Timeout">How long to wait for an answer. Non-positive leaves the wait unbounded.</param>
/// <param name="DenialWillBeLogged">Whether the resolver will log failures as Required denials.</param>
/// <param name="OnBehalf">The active on-behalf session the call is made for, if any.</param>
public readonly record struct IdentityEndpointCall(
    string ServiceName,
    string BaseUrl,
    ClientPrincipal Principal,
    string TenantId,
    string LogIdentifier,
    TimeSpan Timeout,
    bool DenialWillBeLogged = false,
    OnBehalfContext? OnBehalf = null);
