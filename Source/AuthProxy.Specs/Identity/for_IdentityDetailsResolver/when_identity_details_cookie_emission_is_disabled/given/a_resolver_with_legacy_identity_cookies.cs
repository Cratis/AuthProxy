// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_details_cookie_emission_is_disabled.given;

/// <summary>
/// Provides a resolver that has stopped writing the readable identity cookie, for a browser that still holds
/// the one written before that.
/// </summary>
/// <remarks>
/// The cookies are issued with the default setting on, which is what an operator turning it off meets: a
/// browser carrying a copy from before.
/// </remarks>
public class a_resolver_with_legacy_identity_cookies : when_reusing_a_sealed_authorization.given.a_resolver_with_issued_identity_cookies
{
    async Task Establish()
    {
        await IssueIdentityCookies();
        _config.Session.EmitIdentityDetailsCookie = false;
    }

    protected string BobReadableValue => _bobReadableCookie.Split('=', 2)[1];

    protected string AliceReadableValue => _aliceReadableCookie.Split('=', 2)[1];

    protected static bool ExpiresReadableCookie(HttpContext context) =>
        context.Response.Headers.SetCookie.Any(_ => _.StartsWith($"{Cookies.Identity}=;", StringComparison.Ordinal)
            && _.Contains("expires=", StringComparison.OrdinalIgnoreCase));

    protected static bool WritesReadableValue(HttpContext context) =>
        context.Response.Headers.SetCookie.Any(_ => _.StartsWith($"{Cookies.Identity}=", StringComparison.Ordinal)
            && _.Split(';', 2)[0].Split('=', 2)[1].Length > 0);

    protected static bool TouchesReadableCookie(HttpContext context) =>
        context.Response.Headers.SetCookie.Any(_ => _.StartsWith($"{Cookies.Identity}=", StringComparison.Ordinal));

    protected static bool WritesSealedRecord(HttpContext context) =>
        context.Response.Headers.SetCookie.Any(_ => _.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal)
            && _.Split(';', 2)[0].Split('=', 2)[1].Length > 0);
}
