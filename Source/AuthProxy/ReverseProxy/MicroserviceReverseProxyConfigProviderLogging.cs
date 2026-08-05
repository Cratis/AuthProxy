// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

internal static partial class MicroserviceReverseProxyConfigProviderLogging
{
    [LoggerMessage(LogLevel.Warning, "Anonymous path '{Path}' is declared by more than one service. Service '{ServingService}' serves it; the declaration on '{IgnoredService}' has no effect, and requests below that prefix will not reach it.")]
    internal static partial void AnonymousPathAlreadyClaimed(this ILogger logger, string path, string servingService, string ignoredService);
}
