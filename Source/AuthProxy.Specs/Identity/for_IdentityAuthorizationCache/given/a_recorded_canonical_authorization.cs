// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

/// <summary>
/// Provides a recorded canonical authorization and helpers for replaying its protected cookie.
/// </summary>
public class a_recorded_canonical_authorization : Specification
{
    protected const string ProviderKey = "workforce-a";
    protected const string Issuer = "https://identity-a.example.com";
    protected const string Subject = "shared-subject";
    protected const string TenantId = "tenant-a";

    protected IdentityAuthorizationCache _cache;
    protected DefaultHttpContext _replayContext;

    void Establish()
    {
        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configuration.CurrentValue.Returns(new C.AuthProxy
        {
            Session = new C.Session { IdentityRevalidationInterval = TimeSpan.FromMinutes(10) }
        });
        _cache = new IdentityAuthorizationCache(
            new EphemeralDataProtectionProvider(),
            configuration,
            Substitute.For<ILogger<IdentityAuthorizationCache>>());
        _replayContext = Record(CanonicalPrincipal(ProviderKey, Issuer, Subject), TenantId);
    }

    protected DefaultHttpContext Record(ClientPrincipal principal, string tenantId)
    {
        var recordingContext = new DefaultHttpContext();
        _cache.Record(recordingContext, principal, tenantId);
        var setCookie = recordingContext.Response.Headers.SetCookie.Single(_ => _.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal));
        var replayContext = new DefaultHttpContext();
        replayContext.Request.Headers.Cookie = setCookie.Split(';', 2)[0];
        return replayContext;
    }

    protected static ClientPrincipal CanonicalPrincipal(
        string providerKey,
        string issuer,
        string subject,
        IEnumerable<ClientPrincipalClaim>? claims = null) =>
        new()
        {
            IdentityProvider = providerKey,
            UserId = subject,
            Claims = claims ??
            [
                Claim(CanonicalIdentityClaims.ProviderKey, providerKey),
                Claim(CanonicalIdentityClaims.Issuer, issuer),
                Claim(CanonicalIdentityClaims.Subject, subject)
            ]
        };

    protected static ClientPrincipalClaim Claim(string type, string value) => new() { Type = type, Value = value };
}
