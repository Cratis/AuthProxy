// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialLinkInitiation;

/// <summary>
/// OWASP A01 — opening a link URL only shows the confirmation; it never starts the provider challenge.
/// </summary>
/// <param name="harness">The running proxy.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_a_signed_in_browser_opens_a_link_url(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _page;
    string _antiforgeryCookie = string.Empty;
    string _formToken = string.Empty;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var browser = new CredentialLinkBrowser(harness);
        (_page, _antiforgeryCookie, _formToken) = await browser.Open(client, await browser.SignIn(client));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_show_the_confirmation() => Assert.Equal(HttpStatusCode.OK, _page!.StatusCode);

    [Fact]
    public void should_not_redirect_to_the_provider() => Assert.Null(_page!.Headers.Location);

    [Fact]
    public void should_issue_an_antiforgery_cookie() => Assert.NotEmpty(_antiforgeryCookie);

    [Fact]
    public void should_put_a_token_in_the_form() => Assert.NotEmpty(_formToken);
}
