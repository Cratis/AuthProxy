// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialLinkInitiation;

/// <summary>
/// The confirmation the proxy served, submitted with the cookies the browser holds, starts the provider challenge. This also proves the real antiforgery registration is wired into the running proxy.
/// </summary>
/// <param name="harness">The running proxy.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_the_confirmation_form_is_submitted(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _confirmed;
    HttpResponseMessage? _confirmedByAnotherAccount;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var browser = new CredentialLinkBrowser(harness);
        var session = await browser.SignIn(client);
        var (_, cookie, token) = await browser.Open(client, session);
        _confirmed = await browser.Confirm(client, [.. session, cookie], token);

        var anotherAccount = await browser.SignIn(client);
        _confirmedByAnotherAccount = await browser.Confirm(client, [.. anotherAccount, cookie], token);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_redirect_to_the_provider() => Assert.Equal(HttpStatusCode.Found, _confirmed!.StatusCode);

    [Fact]
    public void should_send_the_browser_to_the_provider_authorization_endpoint() =>
        Assert.StartsWith(SessionCookieHarness.ProviderAuthorizationEndpoint, _confirmed!.Headers.Location?.ToString(), StringComparison.Ordinal);

    [Fact]
    public void should_refuse_the_same_form_from_another_account() => Assert.Equal(HttpStatusCode.BadRequest, _confirmedByAnotherAccount!.StatusCode);
}
