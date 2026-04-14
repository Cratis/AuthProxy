// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

internal static partial class TenantResolverLogging
{
    [LoggerMessage(LogLevel.Debug, "Tenant resolved via Specified strategy to {TenantId}")]
    internal static partial void TenantResolvedViaSpecifiedStrategy(this ILogger logger, Guid tenantId);

    [LoggerMessage(LogLevel.Debug, "Tenant resolved via {Strategy} strategy using source identifier '{SourceIdentifier}' to {TenantId}")]
    internal static partial void TenantResolved(this ILogger logger, TenantSourceIdentifierResolverType strategy, string sourceIdentifier, Guid tenantId);

    [LoggerMessage(LogLevel.Warning, "Source identifier '{SourceIdentifier}' resolved by {Strategy} strategy but matched no configured tenant")]
    internal static partial void SourceIdentifierMatchedNoTenant(this ILogger logger, string sourceIdentifier, TenantSourceIdentifierResolverType strategy);

    [LoggerMessage(LogLevel.Warning, "None of the configured tenant resolution strategies could resolve a tenant")]
    internal static partial void NoStrategyResolvedTenant(this ILogger logger);
}
