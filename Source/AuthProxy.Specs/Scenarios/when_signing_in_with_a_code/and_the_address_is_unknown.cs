// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.RegularExpressions;

namespace Cratis.AuthProxy.Scenarios.when_signing_in_with_a_code;

public class and_the_address_is_unknown(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly string _unknown = AuthProxyFactory.NewUnknownAddress();
    readonly string _known = AuthProxyFactory.NewKnownAddress();
    string _unknownPage = string.Empty;
    string _knownPage = string.Empty;
    HttpResponseMessage _guess = null!;
    string _guessPage = string.Empty;

    public async ValueTask InitializeAsync()
    {
        using var client = factory.CreateTestClient();
        var state = await AuthProxyFactory.Start(client);
        _unknownPage = await AuthProxyFactory.Request(client, state, _unknown);
        _knownPage = await AuthProxyFactory.Request(client, await AuthProxyFactory.Start(client), _known);

        var code = factory.Delivery.For(_known).Code;
        var guess = code == "000000" ? "000001" : "000000";
        _guess = await AuthProxyFactory.Verify(client, state, AuthProxyFactory.Field(_unknownPage, "challenge"), guess);
        _guessPage = await _guess.Content.ReadAsStringAsync();
    }

    public ValueTask DisposeAsync()
    {
        _guess.Dispose();
        return ValueTask.CompletedTask;
    }

    static string Shape(string page) => Regex.Replace(page, "(value|data-error)=\"[^\"]*\"|" + Regex.Escape("<strong>") + "[^<]*", string.Empty, RegexOptions.None, TimeSpan.FromSeconds(2));

    [Fact] public void should_show_the_code_page_as_for_a_known_address() => Assert.Contains("Enter your code", _unknownPage);
    [Fact] public void should_look_the_same_as_for_a_known_address() => Assert.Equal(Shape(_knownPage), Shape(_unknownPage));
    [Fact] public void should_give_a_challenge_all_the_same() => Assert.NotEmpty(AuthProxyFactory.Field(_unknownPage, "challenge"));
    [Fact] public void should_not_sign_anyone_in_with_a_guess() => Assert.Equal(HttpStatusCode.OK, _guess.StatusCode);
    [Fact] public void should_answer_a_wrong_code_as_for_a_known_address() => Assert.Contains("did not work", _guessPage);
}
