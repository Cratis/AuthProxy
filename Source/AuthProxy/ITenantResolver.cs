// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Defines the contract for resolving the tenant ID from an incoming HTTP request.
/// </summary>
public interface ITenantResolver
{
    /// <summary>
    /// Tries to resolve the tenant ID from the current request.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="tenantId">The resolved tenant ID, or an empty string when unresolved.</param>
    /// <returns><see langword="true"/> if a tenant was resolved; otherwise <see langword="false"/>.</returns>
    bool TryResolve(HttpContext context, out string tenantId);

    /// <summary>
    /// Tries to resolve tenant metadata from the current request.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="result">The full tenant resolution result when a tenant was resolved.</param>
    /// <returns><see langword="true"/> if a tenant was resolved; otherwise <see langword="false"/>.</returns>
    bool TryResolve(HttpContext context, out TenantResolutionResult result);

    /// <summary>
    /// Evaluates every configured tenant resolution on its own, rather than stopping at the first that resolves.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>The result of every resolution that resolved a tenant, in configuration order.</returns>
    /// <remarks>
    /// Used where every source of a tenant has to agree, such as an on-behalf session pinned to the tenant its grant
    /// was confirmed for: a resolution listed first must not hide a later one addressing a different tenant.
    /// </remarks>
    IEnumerable<TenantResolutionResult> ResolveEach(HttpContext context);
}
