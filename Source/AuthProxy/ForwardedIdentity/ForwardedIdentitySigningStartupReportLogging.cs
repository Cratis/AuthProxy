// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

internal static partial class ForwardedIdentitySigningStartupReportLogging
{
    [LoggerMessage(4, LogLevel.Information, "Forwarded identity for {Flow} to {Service}: {Version}, {State}")]
    internal static partial void FlowRefusing(this ILogger<ForwardedIdentitySigningStartupReport> logger, ForwardedIdentityFlow flow, string? service, string version, string state);

    [LoggerMessage(3, LogLevel.Information, "Forwarded identity for {Flow} to {Service}: attested, not envelope-signed")]
    internal static partial void FlowAttested(this ILogger<ForwardedIdentitySigningStartupReport> logger, ForwardedIdentityFlow flow, string? service);

    [LoggerMessage(0, LogLevel.Information, "Forwarded identity for {Flow} to {Service}: signed with key {KeyId} for audience {Audience}")]
    internal static partial void FlowSigned(this ILogger<ForwardedIdentitySigningStartupReport> logger, ForwardedIdentityFlow flow, string? service, string keyId, string audience);

    [LoggerMessage(2, LogLevel.Information, "Backend transport for {Flow} to {Service}: {Transport}")]
    internal static partial void FlowTransport(this ILogger<ForwardedIdentitySigningStartupReport> logger, ForwardedIdentityFlow flow, string? service, BackendHops.BackendHopTransport transport);

    [LoggerMessage(1, LogLevel.Information, "Forwarded identity for {Flow} to {Service}: not signed")]
    internal static partial void FlowUnsigned(this ILogger<ForwardedIdentitySigningStartupReport> logger, ForwardedIdentityFlow flow, string? service);
}
