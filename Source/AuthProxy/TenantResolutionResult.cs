// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Represents the tenant resolution outcome for a request, including the strategy
/// that produced the tenant and any strategy-specific metadata.
/// </summary>
/// <param name="TenantId">The resolved tenant ID.</param>
/// <param name="Strategy">The strategy that resolved the tenant.</param>
/// <param name="SubHostParentHost">The configured parent host when the SubHost strategy resolved the tenant.</param>
public sealed record TenantResolutionResult(
    string TenantId,
    C.TenantSourceIdentifierResolverType Strategy,
    string? SubHostParentHost = null);