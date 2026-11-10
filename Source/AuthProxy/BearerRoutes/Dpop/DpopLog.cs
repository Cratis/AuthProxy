// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Logs fixed reasons without credential material.</summary>
internal static partial class DpopLog
{
    /// <summary>Logs a bounded proof-refusal reason.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="reason">The fixed reason code.</param>
    [LoggerMessage(LogLevel.Warning, "DPoP refusal: {Reason}")]
    internal static partial void Refused(this ILogger logger, string reason);
}
