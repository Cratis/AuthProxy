// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

internal static partial class TenantResolverLogging
{
    [LoggerMessage(LogLevel.Warning, "None of the configured tenant resolution strategies could resolve a tenant")]
    internal static partial void NoStrategyResolvedTenant(this ILogger logger);
}
