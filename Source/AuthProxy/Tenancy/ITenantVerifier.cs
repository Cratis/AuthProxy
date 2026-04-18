// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Defines a service that checks whether a resolved tenant exists in the platform.
/// </summary>
public interface ITenantVerifier
{
    /// <summary>
    /// Returns <see langword="true"/> when the given <paramref name="tenantId"/> exists,
    /// or when no verification URL is configured (verification is disabled).
    /// Returns <see langword="false"/> when the remote service explicitly reports the tenant
    /// as not found (HTTP 404) or cannot be reached.
    /// </summary>
    /// <param name="tenantId">The tenant identifier to verify.</param>
    /// <param name="urlTemplateOverride">
    /// Optional strategy-specific URL template to use instead of the global
    /// <see cref="Configuration.TenantVerification.UrlTemplate"/>.
    /// </param>
    /// <returns>
    /// A <see cref="Task{TResult}"/> that resolves to <see langword="true"/> if the tenant exists;
    /// otherwise <see langword="false"/>.
    /// </returns>
    Task<bool> VerifyAsync(string tenantId, string? urlTemplateOverride = null);
}
