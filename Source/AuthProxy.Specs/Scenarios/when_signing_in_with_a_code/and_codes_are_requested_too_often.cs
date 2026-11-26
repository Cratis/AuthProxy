// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_signing_in_with_a_code;

public class and_codes_are_requested_too_often(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly string _address = AuthProxyFactory.NewKnownAddress();
    string _first = string.Empty;
    string _third = string.Empty;

    public async ValueTask InitializeAsync()
    {
        using var client = factory.CreateTestClient();
        var state = await AuthProxyFactory.Start(client);
        _first = await AuthProxyFactory.Request(client, state, _address);
        await AuthProxyFactory.Request(client, state, _address);
        _third = await AuthProxyFactory.Request(client, state, _address);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_ask_the_application_only_within_the_limit() => Assert.Equal(2, factory.Delivery.CountFor(_address));
    [Fact] public void should_still_show_the_code_page_over_the_limit() => Assert.Contains("Enter your code", _third);
    [Fact] public void should_not_tell_that_the_limit_was_reached() => Assert.Equal(_first.Contains("Enter your code"), _third.Contains("Enter your code"));
}
