// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

internal static partial class ForwardedIdentitySigningStartupReportLogging
{
    [LoggerMessage(0, LogLevel.Information, "Forwarded identity for {Flow} to {Service}: signed with key {KeyId} for audience {Audience}")]
    internal static partial void FlowSigned(this ILogger<ForwardedIdentitySigningStartupReport> logger, ForwardedIdentityFlow flow, string? service, string keyId, string audience);

    [LoggerMessage(1, LogLevel.Information, "Forwarded identity for {Flow} to {Service}: not signed")]
    internal static partial void FlowUnsigned(this ILogger<ForwardedIdentitySigningStartupReport> logger, ForwardedIdentityFlow flow, string? service);
}
