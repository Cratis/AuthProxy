// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

/// <summary>
/// Provides an actual version-one data-protected authorization cookie and principals for replay specifications.
/// </summary>
public class a_legacy_v1_authorization_cookie : Specification
{
    protected const string UserId = "legacy-user-42";
    protected const string TenantId = "tenant-a";

    const string LegacyProtectorPurpose = "Cratis.AuthProxy.Identity.Authorization.v1";
    EphemeralDataProtectionProvider _dataProtectionProvider;
    protected IdentityAuthorizationCache _cache;

    void Establish()
    {
        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configuration.CurrentValue.Returns(new C.AuthProxy
        {
            Session = new C.Session { IdentityRevalidationInterval = TimeSpan.FromMinutes(10) }
        });
        _dataProtectionProvider = new EphemeralDataProtectionProvider();
        _cache = new IdentityAuthorizationCache(
            _dataProtectionProvider,
            configuration,
            Substitute.For<ILogger<IdentityAuthorizationCache>>());
    }

    protected DefaultHttpContext Replay(long expiresAt, string userId = UserId, string tenantId = TenantId)
    {
        var payload = $"{expiresAt.ToString(CultureInfo.InvariantCulture)}|{userId}|{tenantId}";
        var protectedPayload = _dataProtectionProvider
            .CreateProtector(LegacyProtectorPurpose)
            .Protect(payload);
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{Cookies.IdentityAuthorization}={protectedPayload}";
        return context;
    }

    protected static ClientPrincipal LegacyPrincipal(string userId = UserId) => new()
    {
        IdentityProvider = "legacy-provider",
        UserId = userId
    };

    protected static ClientPrincipal CanonicalPrincipal() => new()
    {
        IdentityProvider = "workforce",
        UserId = UserId,
        Claims =
        [
            new ClientPrincipalClaim { Type = CanonicalIdentityClaims.ProviderKey, Value = "workforce" },
            new ClientPrincipalClaim { Type = CanonicalIdentityClaims.Issuer, Value = "https://identity.example.com" },
            new ClientPrincipalClaim { Type = CanonicalIdentityClaims.Subject, Value = UserId }
        ]
    };
}
