// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Remembers an authorization outcome in a cookie the caller cannot forge.
/// </summary>
/// <remarks>
/// The readable <c>.cratis-identity</c> cookie exists so a frontend can render the signed-in user without
/// a round-trip, which is why it is written non-HTTP-only and in plain base64. That makes it useless as
/// evidence: any script on a proxied origin, and any non-browser client at all, can write whatever it
/// likes into it. This writes the <em>decision</em> to a separate HTTP-only cookie sealed with ASP.NET
/// data protection, so the value that skips the <c>/.cratis/me</c> authorization call is one only
/// AuthProxy can have produced.
/// <para>
/// The sealed payload names the principal and the tenant it was issued for, and both are compared against
/// the current request rather than trusted. Sealing alone would not be enough: a sealed record is still a
/// bearer value, so without the comparison a caller could keep a record issued for one tenant and present
/// it while acting in another, or a record from an old session could authorize whoever holds the browser
/// next. The expiry is carried inside the sealed payload rather than left to the cookie's
/// <c>Max-Age</c>, because <c>Max-Age</c> is a request to the browser and a client that declines to honor
/// it would otherwise hold an authorization that never lapses.
/// </para>
/// </remarks>
/// <param name="dataProtectionProvider">The data protection provider used to seal the record.</param>
/// <param name="config">The auth proxy configuration, providing the re-validation interval.</param>
/// <param name="logger">The logger.</param>
public class IdentityAuthorizationCache(
    IDataProtectionProvider dataProtectionProvider,
    IOptionsMonitor<C.AuthProxy> config,
    ILogger<IdentityAuthorizationCache> logger) : IIdentityAuthorizationCache
{
    /// <summary>
    /// The purpose string binding the protector to this use. A record sealed for one purpose cannot be
    /// unsealed for another, so an unrelated protected value cannot be replayed here.
    /// </summary>
    const string ProtectorPurpose = "Cratis.AuthProxy.Identity.Authorization.v1";

    /// <summary>
    /// The lifetime used when no re-validation interval is configured.
    /// </summary>
    static readonly TimeSpan _defaultLifetime = TimeSpan.FromMinutes(10);

    readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(ProtectorPurpose);

    /// <summary>
    /// Gets how long a recorded authorization stays valid, mirroring the identity cookie's own lifetime.
    /// </summary>
    TimeSpan Lifetime
    {
        get
        {
            var configured = config.CurrentValue.Session.IdentityRevalidationInterval;

            return configured > TimeSpan.Zero ? configured : _defaultLifetime;
        }
    }

    /// <inheritdoc/>
    public void Record(HttpContext context, ClientPrincipal principal, string tenantId)
    {
        var lifetime = Lifetime;
        var expires = DateTimeOffset.UtcNow.Add(lifetime);
        var payload = $"{expires.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)}|{principal.UserId}|{tenantId}";

        context.Response.Cookies.Append(Cookies.IdentityAuthorization, _protector.Protect(payload), new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            MaxAge = lifetime,
            IsEssential = true,
        });
    }

    /// <inheritdoc/>
    public bool IsAuthorized(HttpContext context, ClientPrincipal principal, string tenantId)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.IdentityAuthorization, out var sealedRecord)
            || string.IsNullOrWhiteSpace(sealedRecord))
        {
            return false;
        }

        string payload;

        try
        {
            payload = _protector.Unprotect(sealedRecord);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // Tampered, truncated, or sealed by a key this instance no longer has. Either way it is not
            // evidence of anything, so the caller is re-authorized against the services rather than
            // refused — a rotated data-protection key must not lock everyone out.
            logger.IdentityAuthorizationRecordRejected();
            return false;
        }

        var parts = payload.Split('|', 3);

        return parts.Length == 3
            && long.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var expiresAt)
            && DateTimeOffset.FromUnixTimeSeconds(expiresAt) > DateTimeOffset.UtcNow
            && string.Equals(parts[1], principal.UserId, StringComparison.Ordinal)
            && string.Equals(parts[2], tenantId, StringComparison.OrdinalIgnoreCase);
    }

    /// <inheritdoc/>
    public void Clear(HttpContext context) => context.Response.Cookies.Delete(Cookies.IdentityAuthorization);
}
