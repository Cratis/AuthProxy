// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_signing_in_with_a_code;

public class and_the_address_is_known(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage _challenge = null!;
    HttpResponseMessage _addressPage = null!;
    HttpResponseMessage _codePage = null!;
    HttpResponseMessage _signedIn = null!;
    HttpResponseMessage _reused = null!;
    readonly string _address = AuthProxyFactory.NewKnownAddress();
    string _codePageBody = string.Empty;

    public async ValueTask InitializeAsync()
    {
        using var client = factory.CreateTestClient();

        _challenge = await client.GetAsync("/.cratis/login/code?returnUrl=/");
        var location = _challenge.Headers.Location!.ToString();

        _addressPage = await client.GetAsync(location);
        var state = AuthProxyFactory.Field(await _addressPage.Content.ReadAsStringAsync(), "state");

        _codePage = await client.PostAsync(
            "/signin-code",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["state"] = state, ["step"] = "request", ["email"] = _address }));
        _codePageBody = await _codePage.Content.ReadAsStringAsync();
        var challenge = AuthProxyFactory.Field(_codePageBody, "challenge");
        var code = factory.Delivery.For(_address).Code;

        var verify = new Dictionary<string, string> { ["state"] = state, ["step"] = "verify", ["challenge"] = challenge, ["code"] = code };
        _signedIn = await client.PostAsync("/signin-code", new FormUrlEncodedContent(verify));

        _reused = await client.PostAsync("/signin-code", new FormUrlEncodedContent(verify));
    }

    public ValueTask DisposeAsync()
    {
        _challenge.Dispose();
        _addressPage.Dispose();
        _codePage.Dispose();
        _signedIn.Dispose();
        _reused.Dispose();
        return ValueTask.CompletedTask;
    }

    [Fact] public void should_send_the_browser_to_the_address_page() => Assert.StartsWith("/signin-code?state=", _challenge.Headers.Location!.OriginalString);
    [Fact] public void should_show_the_address_page() => Assert.Equal(HttpStatusCode.OK, _addressPage.StatusCode);
    [Fact] public void should_show_the_code_page() => Assert.Contains("Enter your code", _codePageBody);
    [Fact] public void should_ask_the_application_to_send_a_six_digit_code() => Assert.Matches("^[0-9]{6}$", factory.Delivery.For(_address).Code);
    [Fact] public void should_ask_for_a_sign_in_code() => Assert.Equal("signIn", factory.Delivery.For(_address).Purpose);
    [Fact] public void should_ask_for_the_typed_address() => Assert.Equal(_address, factory.Delivery.For(_address).Email);
    [Fact] public void should_sign_the_person_in() => Assert.Equal(HttpStatusCode.Redirect, _signedIn.StatusCode);
    [Fact] public void should_issue_a_session_cookie() => Assert.NotEmpty(SessionCookies(_signedIn));
    [Fact] public void should_refuse_the_same_code_a_second_time() => Assert.Contains("remote-failure", _reused.Headers.Location!.OriginalString);
    [Fact] public void should_not_issue_a_second_session() => Assert.Empty(SessionCookies(_reused));

    static IEnumerable<string> SessionCookies(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var cookies)
            ? cookies.Where(_ => _.StartsWith($"{C.Session.DefaultCookieName}=", StringComparison.Ordinal) && !_.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase))
            : [];
}
