// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops;

internal static partial class BackendHopTransportStartupReportLogging
{
    [LoggerMessage(0, LogLevel.Information, "Backend TLS trust: {AnchorCount} custom anchors (zero uses system trust); client {Subject}, SAN {SubjectAlternativeName}, SHA-256 {Thumbprint}, expires {NotAfter}")]
    internal static partial void Material(this ILogger<BackendHopTransportStartupReport> logger, int anchorCount, string? subject, string? subjectAlternativeName, string? thumbprint, DateTime? notAfter);

    [LoggerMessage(1, LogLevel.Warning, "LocalDevelopment permits reduced transport protection for signed backend {Backend}; do not use this profile outside a developer machine")]
    internal static partial void LocalException(this ILogger<BackendHopTransportStartupReport> logger, string backend);
}
