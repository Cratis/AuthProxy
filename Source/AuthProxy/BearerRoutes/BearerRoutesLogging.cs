// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

internal static partial class BearerRoutesLogging
{
    [LoggerMessage(LogLevel.Warning, "The metadata at '{MetadataAddress}' does not name the configured issuer '{Issuer}'. Tokens from that issuer are refused until it does.")]
    internal static partial void IssuerMetadataNamesAnotherIssuer(this ILogger logger, string issuer, string metadataAddress);

    [LoggerMessage(LogLevel.Warning, "The metadata or signing keys of issuer '{Issuer}' could not be retrieved from '{MetadataAddress}'.")]
    internal static partial void IssuerMetadataUnavailable(this ILogger logger, Exception exception, string issuer, string metadataAddress);

    [LoggerMessage(LogLevel.Information, "Bearer token refused on route '{Route}' of service '{Service}' ({Status}): {Reason}")]
    internal static partial void BearerTokenRefused(this ILogger logger, string route, string service, BearerTokenValidationStatus status, string reason);

    [LoggerMessage(LogLevel.Information, "A token from bearer-route issuer '{Issuer}' was presented on {Path}, which is not one of its bearer routes. Refused.")]
    internal static partial void BearerTokenOutsideItsRoutes(this ILogger logger, string issuer, string path);

    [LoggerMessage(LogLevel.Information, "A request on bearer route '{Route}' of service '{Service}' has an encoded character, a backslash, a semicolon or a dot segment in its path. Refused.")]
    internal static partial void BearerRoutePathAmbiguous(this ILogger logger, string route, string service);

    [LoggerMessage(LogLevel.Information, "A valid bearer token on route '{Route}' of service '{Service}' does not satisfy the required claim '{Claim}'. Refused.")]
    internal static partial void BearerAccessDenied(this ILogger logger, string route, string service, string claim);

    [LoggerMessage(LogLevel.Warning, "Tenant '{TenantId}' named by a bearer token on {Path} could not be verified. Refused.")]
    internal static partial void BearerTenantNotVerified(this ILogger logger, string tenantId, string path);

    [LoggerMessage(LogLevel.Warning, "Forwarding bearer route '{Route}' of service '{Service}' failed ({Error}).")]
    internal static partial void BearerRouteForwardingFailed(this ILogger logger, Exception? exception, string route, string service, Yarp.ReverseProxy.Forwarder.ForwarderError error);
}
