// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

internal static partial class TenantSelectionMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "Tenant endpoint could not be reached ({ExceptionType})")]
    internal static partial void TenantEndpointUnavailable(this ILogger logger, string exceptionType);

    [LoggerMessage(LogLevel.Warning, "Tenant endpoint returned unexpected status {StatusCode}")]
    internal static partial void TenantEndpointReturnedError(this ILogger logger, int statusCode);

    [LoggerMessage(LogLevel.Warning, "Tenant endpoint did not return a usable response ({ExceptionType})")]
    internal static partial void TenantEndpointReturnedUnusableResponse(this ILogger logger, string exceptionType);
}
