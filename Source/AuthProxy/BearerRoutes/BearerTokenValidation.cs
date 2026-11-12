// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Represents the result of validating the access token on a bearer route.
/// </summary>
/// <param name="Status">The outcome.</param>
/// <param name="Principal">The principal to forward, only when <paramref name="Status"/> is <see cref="BearerTokenValidationStatus.Succeeded"/>.</param>
/// <param name="TenantId">The tenant from the token, only when <paramref name="Status"/> is <see cref="BearerTokenValidationStatus.Succeeded"/>.</param>
/// <param name="Reason">A short, log-safe explanation of a refusal. Never sent to the caller.</param>
public sealed record BearerTokenValidation(
    BearerTokenValidationStatus Status,
    ClaimsPrincipal? Principal = null,
    string? TenantId = null,
    string? Reason = null)
{
    /// <summary>
    /// Gets the environment constraint, when the route requires one.
    /// </summary>
    public string? Environment { get; init; }

    /// <summary>Gets the token's validated sender constraint, before per-request proof verification.</summary>
    public Dpop.DpopSenderConstraint? SenderConstraint { get; init; }

    /// <summary>Gets the standard-base64 JSON sender evidence, only after proof and replay verification.</summary>
    public string SenderBinding { get; init; } = "none";

    /// <summary>
    /// Gets the issuer that signed the accepted token.
    /// </summary>
    public ResolvedBearerIssuer? Issuer { get; init; }

    /// <summary>
    /// Gets a value indicating whether the token was accepted.
    /// </summary>
    public bool Succeeded => Status == BearerTokenValidationStatus.Succeeded;

    /// <summary>Gets the fixed DPoP error for a rejected presentation, without untrusted descriptions.</summary>
    internal string? DpopError { get; init; }

    /// <summary>Gets the exact matched audience before any forwarded claim mappings are applied.</summary>
    internal string? Resource { get; init; }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    /// <param name="principal">The principal to forward.</param>
    /// <param name="tenantId">The tenant from the token.</param>
    /// <returns>The result.</returns>
    public static BearerTokenValidation Success(ClaimsPrincipal principal, string tenantId) =>
        new(BearerTokenValidationStatus.Succeeded, principal, tenantId);

    /// <summary>
    /// Creates a successful result with an environment constraint.
    /// </summary>
    /// <param name="principal">The principal to forward.</param>
    /// <param name="tenantId">The tenant from the token.</param>
    /// <param name="environment">The environment constraint, when the route requires one.</param>
    /// <returns>The result.</returns>
    public static BearerTokenValidation Success(ClaimsPrincipal principal, string tenantId, string? environment) =>
        Success(principal, tenantId) with { Environment = environment };

    /// <summary>
    /// Creates a refusal.
    /// </summary>
    /// <param name="status">The refusal outcome.</param>
    /// <param name="reason">A short, log-safe explanation.</param>
    /// <returns>The result.</returns>
    public static BearerTokenValidation Refused(BearerTokenValidationStatus status, string reason) =>
        new(status, Reason: reason);
}
