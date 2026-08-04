// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the browser-session hardening configuration: how long an authenticated session may live
/// and how often cached identity and tenant context are re-validated against the backing services.
/// </summary>
/// <remarks>
/// All AuthProxy-issued browser cookies are session-scoped or short-lived — closing the browser ends them.
/// These settings additionally bound what a browser that never closes may keep: <see cref="Lifetime"/> caps
/// how long the authentication ticket is honored before the user must re-authenticate with the identity
/// provider, and the re-validation intervals cap how long resolved identity details and a selected tenant
/// are trusted before being confirmed against the backing services again — so revoked access takes effect
/// within the interval without paying a backend round-trip on every request.
/// </remarks>
public class Session
{
    /// <summary>
    /// The configuration section key for the session settings.
    /// </summary>
    public const string SectionKey = $"{AuthProxy.SectionKey}:Session";

    /// <summary>
    /// The default absolute lifetime of an authenticated session.
    /// </summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(12);

    /// <summary>
    /// The default interval at which cached identity details and the selected tenant are re-validated.
    /// </summary>
    public static readonly TimeSpan DefaultRevalidationInterval = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Gets or sets the lifetime of the authentication ticket. When it elapses the user must
    /// re-authenticate with the identity provider, even in a browser session that never closed.
    /// Non-positive values fall back to the default of 12 hours.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = DefaultLifetime;

    /// <summary>
    /// Gets or sets whether the authentication ticket lifetime slides on activity. Disabled by default so
    /// <see cref="Lifetime"/> is an absolute bound that activity cannot extend; enable it to trade bounded
    /// re-authentication for fewer identity-provider round-trips on long-lived sessions.
    /// </summary>
    public bool SlidingExpiration { get; set; }

    /// <summary>
    /// Gets or sets how long the identity-details cookie is trusted before the browser drops it and the
    /// identity details (including whether the user is still authorized) are re-resolved against the
    /// services. Set to zero or a negative value to disable the bound and keep a pure session cookie.
    /// </summary>
    public TimeSpan IdentityRevalidationInterval { get; set; } = DefaultRevalidationInterval;

    /// <summary>
    /// Gets or sets how long a selected tenant is trusted before it is re-validated against the tenant
    /// selection endpoint, so revoked tenant access takes effect without per-request backend calls.
    /// Set to zero or a negative value to disable re-validation.
    /// </summary>
    public TimeSpan TenantRevalidationInterval { get; set; } = DefaultRevalidationInterval;
}
