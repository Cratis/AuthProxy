// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Identity;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Reads and writes the <see cref="Cookies.Tenant"/> cookie. The value is protected with the application's
/// Data Protection key ring and carries the account it was selected for, so a value is only honored for the
/// account that selected it.
/// </summary>
/// <param name="dataProtectionProvider">The data-protection provider.</param>
/// <param name="config">The auth proxy configuration, used to tell whether more than one identity provider is configured.</param>
/// <remarks>
/// Values written by earlier versions hold a plain tenant identifier. They are reported as
/// <see cref="SelectedTenantCookieState.Legacy"/> so the caller can confirm them and write a protected value.
/// </remarks>
public sealed class SelectedTenantCookie(IDataProtectionProvider dataProtectionProvider, IOptionsMonitor<C.AuthProxy>? config = null)
{
    /// <summary>
    /// The data-protection purpose the cookie is sealed under.
    /// </summary>
    public const string Purpose = "Cratis.AuthProxy.SelectedTenant.v1";

    const char ProtectedPrefix = '!';

    readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(Purpose);

    /// <summary>
    /// Removes the selected-tenant cookie.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    public static void Delete(HttpContext context) => context.Response.Cookies.Delete(Cookies.Tenant);

    /// <summary>
    /// Writes the selected-tenant cookie for the signed-in account.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="tenantId">The tenant that was selected.</param>
    /// <returns><see langword="false"/> when the signed-in user has no stable account to bind the selection to; otherwise <see langword="true"/>.</returns>
    public bool TryWrite(HttpContext context, string tenantId)
    {
        if (!TryGetAccount(context, out var account))
        {
            return false;
        }

        var payload = new SelectedTenantCookiePayload(tenantId, account.Kind, account.ProviderKey, account.Issuer, account.Subject);
        context.Response.Cookies.Append(
            Cookies.Tenant,
            ProtectedPrefix + _protector.Protect(JsonSerializer.Serialize(payload)),
            new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = context.Request.IsHttps,
                Path = "/",
            });
        return true;
    }

    /// <summary>
    /// Reads the selected-tenant cookie of the request.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>What the cookie holds.</returns>
    public SelectedTenantCookieValue Read(HttpContext context)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.Tenant, out var value) || string.IsNullOrWhiteSpace(value))
        {
            return SelectedTenantCookieValue.None;
        }

        if (!value.StartsWith(ProtectedPrefix))
        {
            return TenantIdentifier.IsUsable(value)
                ? new(SelectedTenantCookieState.Legacy, value)
                : SelectedTenantCookieValue.Invalid;
        }

        if (!TryGetAccount(context, out var account))
        {
            return SelectedTenantCookieValue.Invalid;
        }

        try
        {
            var payload = JsonSerializer.Deserialize<SelectedTenantCookiePayload>(_protector.Unprotect(value[1..]));
            if (payload is null
                || !TenantIdentifier.IsUsable(payload.TenantId)
                || !string.Equals(payload.Kind, account.Kind, StringComparison.Ordinal)
                || !string.Equals(payload.ProviderKey, account.ProviderKey, StringComparison.Ordinal)
                || !string.Equals(payload.Issuer, account.Issuer, StringComparison.Ordinal)
                || !string.Equals(payload.Subject, account.Subject, StringComparison.Ordinal))
            {
                return SelectedTenantCookieValue.Invalid;
            }

            return new(SelectedTenantCookieState.Bound, payload.TenantId);
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or FormatException)
        {
            return SelectedTenantCookieValue.Invalid;
        }
    }

    bool TryGetAccount(HttpContext context, out IdentityAccountBinding account)
    {
        account = null!;
        var principal = context.BuildClientPrincipal();
        return principal is not null && IdentityAccountBinding.TryCreate(principal, config?.CurrentValue.Authentication.TotalProviderCount ?? 1, out account);
    }
}
