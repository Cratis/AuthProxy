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
    /// The default name of the session cookie.
    /// </summary>
    public const string DefaultCookieName = ".Cratis.AuthProxy.Auth.v2";

    /// <summary>
    /// The default absolute lifetime of an authenticated session.
    /// </summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(12);

    /// <summary>
    /// The default interval at which cached identity details and the selected tenant are re-validated.
    /// </summary>
    public static readonly TimeSpan DefaultRevalidationInterval = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The default duration a resolved identity result is held in the proxy's own memory.
    /// </summary>
    public static readonly TimeSpan DefaultIdentityResultCacheDuration = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets the name of the session cookie. Defaults to <see cref="DefaultCookieName"/>.
    /// </summary>
    /// <remarks>
    /// Set this when a second AuthProxy runs under the same parent domain, or when you share a session cookie
    /// domain across hosts and want the sessions of different proxies kept apart. The name must be an RFC 6265
    /// token, and the <c language="text">__Host-</c> prefix is refused when <see cref="CookieDomain"/> is set because the prefix
    /// forbids a domain. Changing the name signs existing users out once; the old host-only cookie is deleted on
    /// the next sign-in and sign-out.
    /// </remarks>
    public string CookieName { get; set; } = DefaultCookieName;

    /// <summary>
    /// Gets or sets the domain the session cookie is scoped to, for example <c language="text">.cratis.io</c>, so one sign-in
    /// is honored on every host under it. Leave empty — the default — for a host-only cookie, which is today's behavior.
    /// </summary>
    /// <remarks>
    /// Use the narrowest domain that covers every host in <see cref="Service.Hosts"/>. A domain cookie is sent to every
    /// host under the domain, including hosts that are not behind AuthProxy, so a broad domain widens who can replay it.
    /// Startup fails when a declared service host lies outside the domain, when the domain is an IP address or a
    /// bare top-level domain, and when it is combined with <c language="text">SubHost</c> tenant resolution, where the host-only
    /// cookie is what keeps one tenant's session off another tenant's host.
    /// </remarks>
    public string CookieDomain { get; set; } = string.Empty;

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
    /// Gets or sets whether an identity-verification denial terminates the local AuthProxy session before
    /// serving the forbidden response. Disabled by default to preserve the existing refusal behavior.
    /// </summary>
    /// <remarks>
    /// Termination signs out of the local authentication cookie and clears AuthProxy-owned session cookies;
    /// it does not initiate logout at the external identity provider.
    /// </remarks>
    public bool TerminateOnIdentityDenial { get; set; }

    /// <summary>
    /// Gets or sets how long the identity-details cookie is trusted before the browser drops it and the
    /// identity details (including whether the user is still authorized) are re-resolved against the
    /// services. Set to zero or a negative value to disable the bound and keep a pure session cookie.
    /// </summary>
    public TimeSpan IdentityRevalidationInterval { get; set; } = DefaultRevalidationInterval;

    /// <summary>
    /// Gets or sets how long a resolved identity result stays in the proxy's in-memory cache, which
    /// collapses the burst of requests a single page load produces into one round-trip per user and tenant.
    /// Defaults to <see cref="DefaultIdentityResultCacheDuration"/> (30 seconds). Set to zero or a negative
    /// value to resolve on every request.
    /// </summary>
    /// <remarks>
    /// This is server-side memory rather than anything the caller holds, and it caches only positive
    /// results — a refusal is never cached, and a refusal evicts whatever was cached before it. The duration
    /// used to be a hard-coded constant with no way to shorten it, which matters where the identity endpoint
    /// carries an authorization verdict: it is the window in which a revoked user still gets through.
    /// </remarks>
    public TimeSpan IdentityResultCacheDuration { get; set; } = DefaultIdentityResultCacheDuration;

    /// <summary>
    /// Gets or sets how long a selected tenant is trusted before it is re-validated against the tenant
    /// selection endpoint, so revoked tenant access takes effect without per-request backend calls.
    /// Set to zero or a negative value to disable re-validation.
    /// </summary>
    public TimeSpan TenantRevalidationInterval { get; set; } = DefaultRevalidationInterval;
}
