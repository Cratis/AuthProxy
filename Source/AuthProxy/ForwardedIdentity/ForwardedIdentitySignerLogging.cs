// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

internal static partial class ForwardedIdentitySignerLogging
{
    [LoggerMessage(0, LogLevel.Warning, "Forwarded identity for {Flow} to {Service}: signing configuration refused")]
    internal static partial void ConfigurationRefused(this ILogger<ForwardedIdentitySigner> logger, ForwardedIdentityFlow flow, string? service);

    [LoggerMessage(1, LogLevel.Warning, "Forwarded identity for {Flow} to {Service} with key {KeyId}: refused ({Reason})")]
    internal static partial void SigningRefused(this ILogger<ForwardedIdentitySigner> logger, ForwardedIdentityFlow flow, string? service, string keyId, ForwardedIdentityRefusal reason);

    [LoggerMessage(2, LogLevel.Warning, "Forwarded identity for {Flow} to {Service} with key {KeyId}: signing unavailable")]
    internal static partial void SigningFailed(this ILogger<ForwardedIdentitySigner> logger, ForwardedIdentityFlow flow, string? service, string keyId);

    [LoggerMessage(3, LogLevel.Debug, "Forwarded identity for {Flow} to {Service}: signed with key {KeyId}")]
    internal static partial void Signed(this ILogger<ForwardedIdentitySigner> logger, ForwardedIdentityFlow flow, string? service, string keyId);
}
