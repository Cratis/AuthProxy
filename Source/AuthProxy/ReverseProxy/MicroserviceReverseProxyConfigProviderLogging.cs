// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

internal static partial class MicroserviceReverseProxyConfigProviderLogging
{
    [LoggerMessage(LogLevel.Warning, "Anonymous path '{Path}' is declared by more than one service. Service '{ServingService}' serves it; the declaration on '{IgnoredService}' has no effect, and requests below that prefix will not reach it.")]
    internal static partial void AnonymousPathAlreadyClaimed(this ILogger logger, string path, string servingService, string ignoredService);

    [LoggerMessage(LogLevel.Warning, "Anonymous path '{Path}' declared by service '{Service}' was refused ({Reason}) and remains authenticated. Declare a rooted path of plain literal segments, made only of letters, digits, '-', '.', '_' and '~', that does not start with one of the paths AuthProxy reserves for itself.")]
    internal static partial void AnonymousPathRefused(this ILogger logger, string path, string service, AnonymousPathRejection reason);
}
