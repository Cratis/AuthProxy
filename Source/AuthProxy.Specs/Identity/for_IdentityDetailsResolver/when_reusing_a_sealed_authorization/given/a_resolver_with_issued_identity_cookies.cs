// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Cratis.Arc.Identity;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_reusing_a_sealed_authorization.given;

public class a_resolver_with_issued_identity_cookies : when_identity_verification_is_required.given.a_required_verification_resolver
{
    protected const string OtherTenantId = "tenant-b";

    protected ClientPrincipal _alice;
    protected ClientPrincipal _bob;
    protected string _aliceReadableCookie;
    protected string _bobReadableCookie;
    protected string _bobSealedCookie;
    protected int _callsAfterIssuing;
    protected IdentityProviderResult _result;

    void Establish()
    {
        _config.Session.IdentityResultCacheDuration = TimeSpan.Zero;
        _service.IdentityVerification = C.IdentityVerificationMode.BestEffort;
        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configuration.CurrentValue.Returns(_ => _config);
        _authorizationCache = new IdentityAuthorizationCache(new EphemeralDataProtectionProvider(), configuration, Substitute.For<ILogger<IdentityAuthorizationCache>>());
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler, disposeHandler: false));
        _resolver = new IdentityDetailsResolver(configuration, clients, [], _memoryCache, _authorizationCache, _logger);
        _alice = new ClientPrincipal { UserId = "user-a", UserDetails = "Alice" };
        _bob = new ClientPrincipal { UserId = "user-b", UserDetails = "Bob" };
    }

    protected async Task IssueIdentityCookies()
    {
        var aliceCookies = await IssueCookies(_alice, TenantId);
        var bobCookies = await IssueCookies(_bob, TenantId);
        _aliceReadableCookie = aliceCookies.Single(_ => _.StartsWith($"{Cookies.Identity}=", StringComparison.Ordinal));
        _bobReadableCookie = bobCookies.Single(_ => _.StartsWith($"{Cookies.Identity}=", StringComparison.Ordinal));
        _bobSealedCookie = bobCookies.Single(_ => _.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal));
        _callsAfterIssuing = _handler.Calls;
    }

    protected async Task<string[]> IssueCookies(ClientPrincipal principal, string tenant)
    {
        var context = new DefaultHttpContext();
        await _resolver.Resolve(context, principal, tenant);
        return context.Response.Headers.SetCookie.Select(_ => _.Split(';', 2)[0]).ToArray();
    }

    protected static JsonElement ReadableCookieIn(HttpContext context)
    {
        var cookie = context.Response.Headers.SetCookie.Single(_ => _.StartsWith($"{Cookies.Identity}=", StringComparison.Ordinal));
        var value = Uri.UnescapeDataString(cookie.Split(';', 2)[0].Split('=', 2)[1]);
        using var document = JsonDocument.Parse(Convert.FromBase64String(value));
        return document.RootElement.Clone();
    }

    protected void CarryReadableCookie(string value) => _context.Request.Headers.Cookie = $"{_bobSealedCookie}; {Cookies.Identity}={value}";

    protected static string Encode([StringSyntax(StringSyntaxAttribute.Json)] string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
}
