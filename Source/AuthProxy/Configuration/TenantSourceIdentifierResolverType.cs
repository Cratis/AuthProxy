// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Defines the supported strategies for resolving the tenant source identifier.
/// </summary>
public enum TenantSourceIdentifierResolverType
{
    /// <summary>No tenant resolution – tenant ID is left unset.</summary>
    None = 0,

    /// <summary>Resolve the tenant from the request host name, matched against <see cref="Tenant.Domains"/>.</summary>
    Host = 1,

    /// <summary>Resolve the tenant from a claim in the <c>x-ms-client-principal</c>, matched against <see cref="Tenant.SourceIdentifiers"/>.</summary>
    Claim = 2,

    /// <summary>Resolve the tenant from a route segment extracted via a named-group regular expression, matched against <see cref="Tenant.SourceIdentifiers"/>.</summary>
    Route = 3,

    /// <summary>Always resolve to a specific, pre-configured tenant ID (single-tenant deployments).</summary>
    Specified = 4,

    /// <summary>Always resolve to the configured default tenant ID when no other strategy matches.</summary>
    Default = 5,

    /// <summary>Resolve the tenant ID from the request subhost by convention (for example, tenant.example.com -> tenant).</summary>
    SubHost = 6,
}
