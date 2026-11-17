// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

internal static partial class ForwardedIdentitySigningLogging
{
    [LoggerMessage(0, LogLevel.Warning, "Forwarded identity signing refused (Refused)")]
    internal static partial void SigningRefused(this ILogger logger);

    [LoggerMessage(1, LogLevel.Warning, "A request was about to be forwarded with its tenant header repeated; it was collapsed to one value")]
    internal static partial void TenantHeaderRepeated(this ILogger logger);

    [LoggerMessage(2, LogLevel.Error, "A request was refused because its tenant header held conflicting values or a list of values")]
    internal static partial void TenantHeaderRefused(this ILogger logger);
}
