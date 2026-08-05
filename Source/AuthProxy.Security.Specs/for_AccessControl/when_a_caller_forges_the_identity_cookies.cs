// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// OWASP A01 / A08 — the decision that a caller is authorized must not be something the caller can write.
/// <para>
/// AuthProxy asks every configured service's <c>/.cratis/me</c> endpoint whether a signed-in user is
/// authorized at all, and remembers the answer so the question is not re-asked on every proxied request.
/// Where that memory lives is the whole security question. The readable <c>.cratis-identity</c> cookie
/// cannot be it: it is written non-HTTP-only on purpose, so a frontend can render the signed-in user from
/// it, which means script on any proxied origin can rewrite it and any non-browser client can simply send
/// one. Treating its presence as proof meant <c>Cookie: .cratis-identity=x</c> alongside a valid session
/// skipped the authorization call entirely — a user whose access had been revoked stayed authorized for as
/// long as they chose to keep sending it, and no expiry could stop them, because a cookie's
/// <c>Max-Age</c> is a request to the browser rather than a rule.
/// </para>
/// <para>
/// So the authorization answer is remembered in a separate HTTP-only cookie sealed with data protection
/// and bound to the principal and tenant it was issued for. These specs assert the negative that matters:
/// no value a caller can invent for either cookie skips the backend authorization call.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_a_caller_forges_the_identity_cookies(SecurityHarness harness) : IAsyncLifetime
{
    bool _resolvedWithForgedIdentityCookie;
    bool _resolvedWithForgedAuthorizationCookie;
    bool _resolvedWithBothForged;
    bool _resolvedWithNoCookies;

    public async Task InitializeAsync()
    {
        _resolvedWithNoCookies = await IdentityWasResolved("clean", cookies: null);

        _resolvedWithForgedIdentityCookie = await IdentityWasResolved(
            "forged-identity",
            $"{Cookies.Identity}=eyJ1c2VySWQiOiJhdHRhY2tlciJ9");

        _resolvedWithForgedAuthorizationCookie = await IdentityWasResolved(
            "forged-authorization",
            $"{Cookies.IdentityAuthorization}=not-a-real-sealed-record");

        _resolvedWithBothForged = await IdentityWasResolved(
            "forged-both",
            $"{Cookies.Identity}=eyJ1c2VySWQiOiJhdHRhY2tlciJ9; {Cookies.IdentityAuthorization}=AAAAAAAAAAAAAAAAAAAAAA");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_resolve_identity_for_a_caller_presenting_no_cookies() =>
        Assert.True(_resolvedWithNoCookies, "The identity endpoint must be called when nothing is remembered.");

    [Fact]
    public void should_still_resolve_identity_despite_a_forged_readable_cookie() =>
        Assert.True(_resolvedWithForgedIdentityCookie, "A caller-writable cookie must not skip the authorization call.");

    [Fact]
    public void should_still_resolve_identity_despite_a_forged_authorization_cookie() =>
        Assert.True(_resolvedWithForgedAuthorizationCookie, "An unsealable record must not skip the authorization call.");

    [Fact]
    public void should_still_resolve_identity_despite_both_cookies_being_forged() =>
        Assert.True(_resolvedWithBothForged, "No combination of forged cookies may skip the authorization call.");

    /// <summary>
    /// Makes one authenticated request as a brand-new user and reports whether AuthProxy asked the origin
    /// to authorize them.
    /// </summary>
    /// <param name="hint">A label making the user recognizable in a failure.</param>
    /// <param name="cookies">The raw <c>Cookie</c> header to present, if any.</param>
    /// <returns><see langword="true"/> when the origin was asked; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// A fresh user each time, because the resolver also keeps a short-lived server-side cache keyed by
    /// user and tenant — a shared identity would let an earlier request's answer stand in for this one and
    /// the spec would pass without proving anything.
    /// </remarks>
    async Task<bool> IdentityWasResolved(string hint, string? cookies)
    {
        using var client = harness.CreateSecurityClient();

        var request = SecurityHarness.Authenticated(
            HttpMethod.Get,
            SecurityHarness.ProtectedPath,
            SecurityHarness.UniqueUser(hint));

        if (cookies is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookies);
        }

        harness.Origin.Clear();
        await client.SendAsync(request);

        return harness.Origin.ReceivedAnythingFor(WellKnownPaths.IdentityDetails);
    }
}
