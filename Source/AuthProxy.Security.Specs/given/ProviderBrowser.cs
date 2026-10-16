// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.WebUtilities;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Plays the browser and the identity provider between them through one whole sign-in, a hop at a time.
/// </summary>
/// <remarks>
/// The client keeps no cookies and follows no redirects, so every hop is visible and a cookie reaches only the host it
/// was set for — the one thing a spec about where a handshake runs cannot do without.
/// </remarks>
public static class ProviderBrowser
{
    /// <summary>
    /// Signs in through the provider, starting on a host.
    /// </summary>
    /// <param name="client">The client to send with.</param>
    /// <param name="startHost">The host the person starts on.</param>
    /// <param name="returnUrl">The return URL the sign-in carries.</param>
    /// <returns>Every hop of the sign-in.</returns>
    public static async Task<Handshake> SignIn(HttpClient client, string startHost, string returnUrl)
    {
        var loginPath = $"{WellKnownPaths.LoginPrefix}/{SessionCookieHarness.ProviderScheme}?returnUrl={Uri.EscapeDataString(returnUrl)}";
        var first = await client.SendAsync(SessionCookieHarness.Request(startHost, loginPath));

        var challenge = first;
        var challengeHost = startHost;
        HttpResponseMessage? bounce = null;
        if (IsRedirectToAnotherHost(first, startHost, out var bounceTarget))
        {
            bounce = first;
            challengeHost = bounceTarget.Authority;
            challenge = await client.SendAsync(SessionCookieHarness.Request(challengeHost, bounceTarget.PathAndQuery));
        }

        var challengeCookies = CookiePairs(challenge);
        var location = challenge.Headers.Location;
        if (location?.ToString().StartsWith(SessionCookieHarness.ProviderAuthorizationEndpoint, StringComparison.Ordinal) != true)
        {
            return new Handshake(bounce, challenge, challengeHost, null, []);
        }

        var state = QueryHelpers.ParseQuery(location.Query)["state"].ToString();
        var callback = await client.SendAsync(SessionCookieHarness.Request(
            challengeHost,
            $"/signin-{SessionCookieHarness.ProviderScheme}?code=test-code&state={Uri.EscapeDataString(state)}",
            [.. challengeCookies]));

        return new Handshake(bounce, challenge, challengeHost, callback, SessionCookieHarness.SessionFrom(callback));
    }

    static bool IsRedirectToAnotherHost(HttpResponseMessage response, string host, out Uri target)
    {
        target = response.Headers.Location!;
        return response.StatusCode == HttpStatusCode.Found
            && target is { IsAbsoluteUri: true }
            && !string.Equals(target.Authority, host, StringComparison.OrdinalIgnoreCase)
            && target.AbsolutePath.StartsWith(WellKnownPaths.LoginPrefix, StringComparison.Ordinal);
    }

    static string[] CookiePairs(HttpResponseMessage response) =>
        [.. SessionCookieHarness.SetCookies(response)
            .Select(_ => _.Split(';')[0])
            .Where(_ => _.Split('=', 2) is [_, { Length: > 0 }])];

    /// <summary>
    /// One whole sign-in.
    /// </summary>
    /// <param name="Bounce">The response that sent the browser to another host first, when one did.</param>
    /// <param name="Challenge">The response that sent the browser to the identity provider.</param>
    /// <param name="ChallengeHost">The host the challenge was issued on.</param>
    /// <param name="Callback">The response to the provider's callback, when the challenge reached the provider.</param>
    /// <param name="Session">The session cookies the callback set.</param>
    public sealed record Handshake(
        HttpResponseMessage? Bounce,
        HttpResponseMessage Challenge,
        string ChallengeHost,
        HttpResponseMessage? Callback,
        IReadOnlyList<string> Session);
}
