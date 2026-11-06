// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_the_service_is_not_signed : given.a_sender
{
    async Task Because() => _delivered = await _sender.Send(CreateRequest(), CancellationToken.None);

    [Fact] void should_deliver_the_callback() => _delivered.ShouldBeTrue();
    [Fact] void should_use_the_default_client() => _factory.Received(1).CreateClient(string.Empty);
    [Fact] void should_not_include_a_signature() => _handler.LastRequest!.Headers.Contains("x-cratis-forwarded-identity-signature").ShouldBeFalse();
}
