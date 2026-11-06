// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_the_callback_has_no_identity_to_sign : given.a_sender
{
    protected override ForwardedIdentitySigningOutcome SigningOutcome => ForwardedIdentitySigningOutcome.NotIdentityBearing;

    async Task Because() => _delivered = await _sender.Send(CreateRequest(), CancellationToken.None);

    [Fact] void should_not_deliver_the_callback() => _delivered.ShouldBeFalse();
    [Fact] void should_not_create_a_client() => _factory.DidNotReceive().CreateClient(Arg.Any<string>());
}
