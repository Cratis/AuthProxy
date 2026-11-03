// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.RegularExpressions;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Drives the credential-link confirmation the way a browser does: open the link, read the form it was served,
/// and submit it with the cookies the browser holds.
/// </summary>
/// <param name="harness">The running proxy.</param>
public sealed partial class CredentialLinkBrowser(SessionCookieHarness harness)
{
    /// <summary>The path of the link flow for the harness's provider.</summary>
    public static readonly string LinkPath = $"{WellKnownPaths.Link}/{SessionCookieHarness.ProviderScheme}";

    /// <summary>The link token every request carries.</summary>
    public const string LinkToken = "a-link-token";

    /// <summary>
    /// Opens the link URL with the given session and returns the response, the form's antiforgery cookie and its token.
    /// </summary>
    /// <param name="client">The client to use.</param>
    /// <param name="session">The session cookies of the signed-in caller.</param>
    /// <returns>The page, the antiforgery cookie pair, and the form token.</returns>
    public async Task<(HttpResponseMessage Page, string AntiforgeryCookie, string FormToken)> Open(HttpClient client, string[] session)
    {
        var page = await client.SendAsync(SessionCookieHarness.Request(
            SessionCookieHarness.ConsoleHost,
            $"{LinkPath}?token={LinkToken}",
            session));
        var cookie = SessionCookieHarness.SessionFrom(page).FirstOrDefault(_ => _.StartsWith($"{Cookies.Antiforgery}=", StringComparison.Ordinal)) ?? string.Empty;
        // The page HTML-encodes the value as the attribute is written; a browser decodes it before posting the form.
        var token = System.Net.WebUtility.HtmlDecode(FormTokenPattern.Match(await page.Content.ReadAsStringAsync()).Groups["token"].Value);
        return (page, cookie, token);
    }

    /// <summary>
    /// Submits the confirmation form.
    /// </summary>
    /// <param name="client">The client to use.</param>
    /// <param name="cookies">The cookies to send.</param>
    /// <param name="formToken">The antiforgery token for the form body, or <see langword="null"/> to omit it.</param>
    /// <param name="queryToken">An antiforgery token to put in the query string only, or <see langword="null"/>.</param>
    /// <returns>The response.</returns>
    public Task<HttpResponseMessage> Confirm(HttpClient client, string[] cookies, string? formToken, string? queryToken = null)
    {
        var fields = new Dictionary<string, string> { ["token"] = LinkToken };
        if (formToken is not null)
        {
            fields[ProxyAntiforgery.FormFieldName] = formToken;
        }

        var query = queryToken is null ? string.Empty : $"&{ProxyAntiforgery.FormFieldName}={Uri.EscapeDataString(queryToken)}";
        var request = SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, $"{LinkPath}?x=1{query}", cookies);
        request.Method = HttpMethod.Post;
        request.Content = new FormUrlEncodedContent(fields);
        return client.SendAsync(request);
    }

    /// <summary>
    /// Confirms a link and returns the provider's state value and the handshake cookies the browser was given.
    /// </summary>
    /// <param name="client">The client to use.</param>
    /// <param name="session">The session cookies of the signed-in caller.</param>
    /// <returns>The state sent to the provider and the correlation cookie pairs.</returns>
    public async Task<(string State, string[] Handshake)> Start(HttpClient client, string[] session)
    {
        var (_, cookie, token) = await Open(client, session);
        var challenge = await Confirm(client, [.. session, cookie], token);
        var query = System.Web.HttpUtility.ParseQueryString(challenge.Headers.Location!.Query);
        var handshake = SessionCookieHarness.SessionFrom(challenge).Where(_ => _.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal)).ToArray();
        return (query["state"]!, handshake);
    }

    /// <summary>
    /// Delivers the provider's callback to the proxy.
    /// </summary>
    /// <param name="client">The client to use.</param>
    /// <param name="state">The state value the callback carries.</param>
    /// <param name="cookies">The cookies the browser sends along.</param>
    /// <returns>The response.</returns>
    public Task<HttpResponseMessage> Callback(HttpClient client, string state, params string[] cookies) =>
        client.SendAsync(SessionCookieHarness.Request(
            SessionCookieHarness.ConsoleHost,
            $"/signin-{SessionCookieHarness.ProviderScheme}?code=provider-code&state={Uri.EscapeDataString(state)}",
            cookies));

    /// <summary>
    /// Signs a new caller in and returns the session cookies.
    /// </summary>
    /// <param name="client">The client to use.</param>
    /// <returns>The session cookies.</returns>
    public async Task<string[]> SignIn(HttpClient client) =>
        SessionCookieHarness.SessionFrom(await harness.SignIn(client, SessionCookieHarness.ConsoleHost));

    [GeneratedRegex("name=\"__cratis_antiforgery\" value=\"(?<token>[^\"]*)\"", RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
    private static partial Regex FormTokenPattern { get; }
}
