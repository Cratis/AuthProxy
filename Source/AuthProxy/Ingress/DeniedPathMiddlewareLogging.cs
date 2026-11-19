// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress;

internal static partial class DeniedPathMiddlewareLogging
{
    [LoggerMessage(LogLevel.Debug, "Request refused by the configured path boundary")]
    internal static partial void PathRefused(this ILogger logger);
}
