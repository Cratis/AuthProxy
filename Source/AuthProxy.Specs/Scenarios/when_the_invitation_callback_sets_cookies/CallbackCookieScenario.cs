// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

namespace Cratis.AuthProxy.Scenarios.when_the_invitation_callback_sets_cookies;

/// <summary>
/// Plays an invitation sign-in through the real OIDC pipeline while the browser holds the cookies earlier, abandoned
/// attempts left behind, and measures what the callback answers with.
/// </summary>
public sealed class CallbackCookieScenario
{
    /// <summary>Gets the names of the correlation and nonce cookies the stale handshakes left behind.</summary>
    public IReadOnlyList<string> StaleHandshakeNames { get; private set; } = [];

    /// <summary>Gets the Set-Cookie headers the stale handshakes' challenges wrote for correlation and nonce cookies.</summary>
    public IReadOnlyList<string> StaleHandshakeSetCookies { get; private set; } = [];

    /// <summary>Gets when the scenario started, to compare cookie expiries against.</summary>
    public DateTimeOffset StartedAt { get; private set; }

    /// <summary>Gets the sign-in round trip.</summary>
    public OidcCallbackAuthProxyFactory.ProviderSignIn SignIn { get; private set; } = null!;

    /// <summary>Gets the callback measurement.</summary>
    public CallbackCookieMeasurement Measurement { get; private set; } = null!;

    /// <summary>Gets the cookie pairs the current attempt's challenge set.</summary>
    public IReadOnlyList<string> CurrentHandshakeCookies { get; private set; } = [];

    /// <summary>Gets the Set-Cookie headers of the callback.</summary>
    public IReadOnlyList<string> CallbackSetCookies { get; private set; } = [];

    /// <summary>
    /// Runs the scenario.
    /// </summary>
    /// <param name="factory">The factory.</param>
    /// <param name="title">The name written with the measurement table.</param>
    /// <param name="staleHandshakes">How many abandoned handshakes the browser still holds cookies for.</param>
    /// <param name="staleSession">Whether the browser holds a stale chunked session cookie.</param>
    /// <returns>The asynchronous operation.</returns>
    public async Task Run(CallbackCookiesAuthProxyFactory factory, string title, int staleHandshakes, bool staleSession)
    {
        factory.Reset();
        StartedAt = DateTimeOffset.UtcNow;
        using var browser = factory.CreateBrowser(factory.BrowserBase);

        var stale = new List<string>();
        var staleSetCookies = new List<string>();
        for (var attempt = 0; attempt < staleHandshakes; attempt++)
        {
            var challenge = await browser.GetAsync($"/invite/{NewToken(factory)}");
            stale.AddRange(OidcCallbackAuthProxyFactory.CookiesFrom(challenge).Where(IsHandshakeCookie));
            if (challenge.Headers.TryGetValues("Set-Cookie", out var written))
            {
                staleSetCookies.AddRange(written.Where(IsHandshakeCookie));
            }
        }

        StaleHandshakeSetCookies = staleSetCookies;
        StaleHandshakeNames = [.. stale.Select(pair => pair.Split('=', 2)[0])];
        if (staleSession)
        {
            stale.AddRange(StaleSessionChunks());
        }

        SignIn = await factory.SignInThroughProvider(
            browser,
            $"/invite/{NewToken(factory)}",
            transformCallbackCookies: current =>
            {
                CurrentHandshakeCookies = current;
                return [.. stale, .. current];
            });

        Measurement = CallbackCookieMeasurement.Of(SignIn.Callback);
        Measurement.WriteTable(title);
        CallbackSetCookies = SignIn.Callback.Headers.TryGetValues("Set-Cookie", out var values) ? [.. values] : [];
    }

    static bool IsHandshakeCookie(string pair) =>
        pair.StartsWith(Cookies.CorrelationPrefix, StringComparison.Ordinal) || pair.StartsWith(Cookies.NoncePrefix, StringComparison.Ordinal);

    static string NewToken(OidcCallbackAuthProxyFactory factory) =>
        TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim(OidcCallbackAuthProxyFactory.TenantClaim, OidcCallbackAuthProxyFactory.TenantId),
                new Claim("email", OidcCallbackAuthProxyFactory.DefaultEmail),
            ]);

    static string[] StaleSessionChunks()
    {
        const string name = OidcCallbackAuthProxyFactory.SessionCookieName;
        return
        [
            $"{name}=chunks-3",
            $"{name}C1={RandomValue(3900)}",
            $"{name}C2={RandomValue(3900)}",
            $"{name}C3={RandomValue(1200)}",
        ];
    }

    static string RandomValue(int length) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(length * 3 / 4)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
