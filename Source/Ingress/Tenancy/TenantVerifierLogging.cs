// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Tenancy;

/// <summary>
/// Holds the log messages for <see cref="TenantVerifier"/>.
/// </summary>
internal static partial class TenantVerifierLogging
{
    /// <summary>
    /// Logs that a tenant was not found by the verification service.
    /// </summary>
    /// <param name="logger">The logger to write to.</param>
    /// <param name="tenantId">The tenant identifier that was not found.</param>
    [LoggerMessage(LogLevel.Warning, "Tenant '{TenantId}' was not found by the verification service.")]
    internal static partial void TenantNotFound(this ILogger<TenantVerifier> logger, Guid tenantId);

    /// <summary>
    /// Logs a non-success, non-404 HTTP status code returned by the tenant verification service.
    /// </summary>
    /// <param name="logger">The logger to write to.</param>
    /// <param name="tenantId">The tenant identifier being verified.</param>
    /// <param name="statusCode">The unexpected HTTP status code.</param>
    [LoggerMessage(LogLevel.Warning, "Tenant verification for '{TenantId}' returned unexpected status {StatusCode}.")]
    internal static partial void TenantVerificationFailed(this ILogger<TenantVerifier> logger, Guid tenantId, int statusCode);

    /// <summary>
    /// Logs an exception thrown while contacting the tenant verification service.
    /// </summary>
    /// <param name="logger">The logger to write to.</param>
    /// <param name="exception">The exception that was thrown.</param>
    /// <param name="tenantId">The tenant identifier being verified.</param>
    /// <param name="url">The URL that was contacted.</param>
    [LoggerMessage(LogLevel.Error, "Error contacting tenant verification service for '{TenantId}' at '{Url}'.")]
    internal static partial void TenantVerificationError(this ILogger<TenantVerifier> logger, Exception exception, Guid tenantId, string url);
}
