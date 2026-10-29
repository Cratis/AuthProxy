// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

internal static partial class ForwardingPathMiddlewareLogging
{
    [LoggerMessage(LogLevel.Information, "Refused to forward {Method} {Path} to service '{Service}' ({Reason})")]
    internal static partial void Refused(this ILogger<ForwardingPathMiddleware> logger, string method, string path, string service, ForwardingPathRefusal reason);
}
