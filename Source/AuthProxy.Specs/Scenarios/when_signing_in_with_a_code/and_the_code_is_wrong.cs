// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_signing_in_with_a_code;

public class and_the_code_is_wrong(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly string _address = AuthProxyFactory.NewKnownAddress();
    readonly List<HttpResponseMessage> _wrong = [];
    HttpResponseMessage _rightAfterwards = null!;
    string _afterExhaustion = string.Empty;

    public async ValueTask InitializeAsync()
    {
        using var client = factory.CreateTestClient();
        var state = await AuthProxyFactory.Start(client);
        var challenge = AuthProxyFactory.Field(await AuthProxyFactory.Request(client, state, _address), "challenge");
        var code = factory.Delivery.For(_address).Code;
        var wrong = code == "111111" ? "222222" : "111111";

        for (var attempt = 0; attempt < 3; attempt++)
        {
            _wrong.Add(await AuthProxyFactory.Verify(client, state, challenge, wrong));
        }

        _afterExhaustion = await _wrong[^1].Content.ReadAsStringAsync();
        _rightAfterwards = await AuthProxyFactory.Verify(client, state, challenge, code);
    }

    public ValueTask DisposeAsync()
    {
        _wrong.ForEach(_ => _.Dispose());
        _rightAfterwards.Dispose();
        return ValueTask.CompletedTask;
    }

    [Fact] public void should_not_sign_in_with_a_wrong_code() => Assert.All(_wrong, _ => Assert.Equal(System.Net.HttpStatusCode.OK, _.StatusCode));
    [Fact] public void should_ask_for_a_new_code_when_the_attempts_run_out() => Assert.Contains("can no longer be used", _afterExhaustion);
    [Fact] public void should_refuse_the_right_code_after_the_attempts_ran_out() => Assert.Equal(System.Net.HttpStatusCode.OK, _rightAfterwards.StatusCode);
}
