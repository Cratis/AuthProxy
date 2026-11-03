// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialLinkInitiation;

/// <summary>
/// OWASP A01 / CSRF — a cross-site form carries the victim's session cookie but not the antiforgery cookie and token, so it must not start a link.
/// </summary>
/// <param name="harness">The running proxy.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_a_form_from_another_site_confirms_a_link(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _withoutAnything;
    HttpResponseMessage? _withQueryTokenOnly;
    HttpResponseMessage? _withAnotherBrowsersToken;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var browser = new CredentialLinkBrowser(harness);
        var victim = await browser.SignIn(client);
        var (_, victimCookie, victimToken) = await browser.Open(client, victim);

        _withoutAnything = await browser.Confirm(client, victim, formToken: null);
        _withQueryTokenOnly = await browser.Confirm(client, [.. victim, victimCookie], formToken: null, queryToken: victimToken);

        var attacker = await browser.SignIn(client);
        var (_, _, attackerToken) = await browser.Open(client, attacker);
        _withAnotherBrowsersToken = await browser.Confirm(client, [.. victim, victimCookie], attackerToken);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_refuse_a_form_without_the_antiforgery_cookie_and_token() => Assert.Equal(HttpStatusCode.BadRequest, _withoutAnything!.StatusCode);

    [Fact]
    public void should_refuse_a_token_that_is_only_in_the_query_string() => Assert.Equal(HttpStatusCode.BadRequest, _withQueryTokenOnly!.StatusCode);

    [Fact]
    public void should_refuse_a_token_issued_to_another_browser() => Assert.Equal(HttpStatusCode.BadRequest, _withAnotherBrowsersToken!.StatusCode);

    [Fact]
    public void should_not_redirect_to_the_provider() =>
        Assert.All([_withoutAnything, _withQueryTokenOnly, _withAnotherBrowsersToken], _ => Assert.Null(_!.Headers.Location));
}
