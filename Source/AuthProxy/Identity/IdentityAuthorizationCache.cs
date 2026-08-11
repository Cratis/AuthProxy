// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.AspNetCore.DataProtection;
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
/// The versioned structured payload names the principal's account binding and the tenant it was issued for,
/// and both are compared against the current request rather than trusted. A canonical binding contains the
/// complete provider, normalized issuer, and subject tuple; a legacy binding preserves the released user-ID
/// behavior. Sealing alone would not be enough: a sealed record is still a
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
    Microsoft.Extensions.Options.IOptionsMonitor<C.AuthProxy> config,
    ILogger<IdentityAuthorizationCache> logger) : IIdentityAuthorizationCache
{
    /// <summary>
    /// The original purpose string retained only to validate unexpired legacy-principal records issued by version one.
    /// </summary>
    const string LegacyProtectorPurpose = "Cratis.AuthProxy.Identity.Authorization.v1";

    /// <summary>
    /// The purpose string for versioned structured authorization records.
    /// </summary>
    const string ProtectorPurpose = "Cratis.AuthProxy.Identity.Authorization.v2";

    /// <summary>
    /// The lifetime used when no re-validation interval is configured.
    /// </summary>
    static readonly TimeSpan _defaultLifetime = TimeSpan.FromMinutes(10);

    readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(ProtectorPurpose);
    readonly IDataProtector _legacyProtector = dataProtectionProvider.CreateProtector(LegacyProtectorPurpose);

    /// <summary>
    /// Gets how long a recorded authorization stays valid, mirroring the identity cookie's own lifetime,
    /// or <see langword="null"/> when nothing may be recorded at all.
    /// </summary>
    /// <remarks>
    /// A non-positive re-validation interval is documented as "no bound", and falling back to ten minutes
    /// quietly turned that into the longest lifetime the setting can produce. That is a harmless
    /// contradiction while the record only saves a round-trip, and a serious one once it carries an
    /// authorization decision: a deployment that asked for no remembered authorization would be handed the
    /// most permissive one. So where the identity endpoint is a verifier, "no bound" is honored by
    /// recording nothing; everywhere else the released fallback is kept, because changing it unconditionally
    /// would multiply identity-endpoint traffic for deployments that set zero for its documented meaning.
    /// </remarks>
    TimeSpan? Lifetime
    {
        get
        {
            var current = config.CurrentValue;
            var configured = current.Session.IdentityRevalidationInterval;
            if (configured > TimeSpan.Zero)
            {
                return configured;
            }

            return current.RequiresIdentityVerification ? null : _defaultLifetime;
        }
    }

    /// <inheritdoc/>
    public void Record(HttpContext context, ClientPrincipal principal, string tenantId)
    {
        if (!IdentityAccountBinding.TryCreate(principal, out var account))
        {
            return;
        }

        if (Lifetime is not { } lifetime)
        {
            return;
        }

        var expires = DateTimeOffset.UtcNow.Add(lifetime);
        var payload = JsonSerializer.Serialize(new IdentityAuthorizationRecord
        {
            Version = IdentityAuthorizationRecord.CurrentVersion,
            ExpiresAt = expires.ToUnixTimeSeconds(),
            TenantId = tenantId,
            Account = account
        });

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
        if (!IdentityAccountBinding.TryCreate(principal, out var account))
        {
            return false;
        }

        if (!context.Request.Cookies.TryGetValue(Cookies.IdentityAuthorization, out var sealedRecord)
            || string.IsNullOrWhiteSpace(sealedRecord))
        {
            return false;
        }

        try
        {
            var payload = _protector.Unprotect(sealedRecord);
            var record = JsonSerializer.Deserialize<IdentityAuthorizationRecord>(payload);
            return record?.Version == IdentityAuthorizationRecord.CurrentVersion
                && record.Account is not null
                && record.ExpiresAt > DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                && string.Equals(record.TenantId, tenantId, StringComparison.OrdinalIgnoreCase)
                && record.Account == account;
        }
        catch (System.Security.Cryptography.CryptographicException) when (!account.IsCanonical)
        {
            return IsAuthorizedByLegacyRecord(sealedRecord, account, tenantId);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return RejectRecord();
        }
        catch (JsonException)
        {
            return RejectRecord();
        }
    }

    /// <inheritdoc/>
    public void Clear(HttpContext context) => context.Response.Cookies.Delete(Cookies.IdentityAuthorization);

    bool IsAuthorizedByLegacyRecord(string sealedRecord, IdentityAccountBinding account, string tenantId)
    {
        if (account.Subject.Contains('|') || tenantId.Contains('|'))
        {
            return RejectRecord();
        }

        string payload;
        try
        {
            payload = _legacyProtector.Unprotect(sealedRecord);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return RejectRecord();
        }

        var parts = payload.Split('|', 3);

        return parts.Length == 3
            && long.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var expiresAt)
            && expiresAt > DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            && string.Equals(parts[1], account.Subject, StringComparison.Ordinal)
            && string.Equals(parts[2], tenantId, StringComparison.OrdinalIgnoreCase);
    }

    bool RejectRecord()
    {
        // Tampered, truncated, malformed, or sealed by a key this instance no longer has. It is not evidence
        // of authorization, so the caller is re-authorized against the services rather than refused.
        logger.IdentityAuthorizationRecordRejected();
        return false;
    }
}
