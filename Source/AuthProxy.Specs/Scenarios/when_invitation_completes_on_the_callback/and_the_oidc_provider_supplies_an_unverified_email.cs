// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end OIDC scenario: a real discovery/JWKS/token/userinfo round trip completes canonical identity
/// resolution for real, but the identity provider's <c language="text">email_verified</c> claim is explicitly false. This
/// is answered with the dedicated email-mismatch outcome, never a generic denial and never a silent
/// success.
/// </summary>
/// <param name="factory">The shared OIDC application factory.</param>
/// <remarks>
/// The status code alone cannot show this: every invitation refusal answers 403. The page body is the only
/// observable that tells the three outcomes apart, so it is asserted in both directions - the specific page
/// is present, and the generic invalid-link page it used to collapse into is not.
/// </remarks>
public class and_the_oidc_provider_supplies_an_unverified_email(OidcCallbackAuthProxyFactory factory) : IClassFixture<OidcCallbackAuthProxyFactory>, IAsyncLifetime
{
    OidcCallbackAuthProxyFactory.ProviderSignIn _signIn;
    string _callbackBody;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        factory.Reset();
        factory.IdentityClaims = new Dictionary<string, string>
        {
            ["email"] = OidcCallbackAuthProxyFactory.DefaultEmail,
            ["email_verified"] = "false",
            ["acr"] = OidcCallbackAuthProxyFactory.DefaultAssurance,
        };

        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim(OidcCallbackAuthProxyFactory.TenantClaim, OidcCallbackAuthProxyFactory.TenantId),
                new Claim("email", "invitee@example.com"),
            ]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;
        _signIn = await factory.SignInThroughProvider(browser, $"/invite/{token}");
        _callbackBody = await _signIn.Callback.Content.ReadAsStringAsync();
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_not_call_the_completion_endpoint() =>
        Assert.Equal(0, _exchangeCallsDuringFlow);

    [Fact]
    public void should_refuse_the_completion() =>
        Assert.Equal(HttpStatusCode.Forbidden, _signIn.Callback.StatusCode);

    [Fact]
    public void should_answer_with_the_email_mismatch_page() =>
        Assert.Contains("Email Mismatch", _callbackBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_answer_with_the_generic_invalid_link_page() =>
        Assert.DoesNotContain("Invitation Invalid", _callbackBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_answer_with_the_email_unavailable_page() =>
        Assert.DoesNotContain("Email Unavailable", _callbackBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_redirect_to_lobby() =>
        Assert.Null(_signIn.Callback.Headers.Location);
}
