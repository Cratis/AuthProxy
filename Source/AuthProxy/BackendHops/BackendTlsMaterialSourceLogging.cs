// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops;

internal static partial class BackendTlsMaterialSourceLogging
{
    [LoggerMessage(0, LogLevel.Information, "Backend TLS material reloaded: {Subject}, SHA-256 {Thumbprint}, expires {NotAfter}, {AnchorCount} custom anchors")]
    internal static partial void MaterialReloaded(this ILogger<BackendTlsMaterialSource> logger, string? subject, string? thumbprint, DateTime? notAfter, int anchorCount);

    [LoggerMessage(1, LogLevel.Warning, "Backend TLS reload refused; keeping previous material: {Problem}")]
    internal static partial void ReloadRefused(this ILogger<BackendTlsMaterialSource> logger, string problem);

    [LoggerMessage(2, LogLevel.Error, "The current backend TLS client certificate has expired")]
    internal static partial void ClientExpired(this ILogger<BackendTlsMaterialSource> logger);
}
