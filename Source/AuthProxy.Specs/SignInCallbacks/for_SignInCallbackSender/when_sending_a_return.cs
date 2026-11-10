// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_sending_a_return : given.a_sender
{
    JsonElement _body;

    async Task Because()
    {
        _delivered = await _sender.Send(CreateRequest(SignInCallbackKind.Returned), CancellationToken.None);
        _body = JsonElement.Parse(_handler.LastRequestBody!);
    }

    [Fact] void should_mark_the_call_as_a_return() => Header(Headers.SignInCallback).ShouldEqual("Returned");
    [Fact] void should_name_the_kind() => _body.GetProperty("kind").GetString().ShouldEqual("Returned");
}
