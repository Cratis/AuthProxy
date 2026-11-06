// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_signing_is_refused : given.a_sender
{
    protected override ForwardedIdentitySigningOutcome SigningOutcome => ForwardedIdentitySigningOutcome.Refused;

    async Task Because() => _delivered = await _sender.Send(CreateRequest(), CancellationToken.None);

    [Fact] void should_not_deliver_the_callback() => _delivered.ShouldBeFalse();
    [Fact] void should_not_create_a_client() => _factory.DidNotReceive().CreateClient(Arg.Any<string>());
    [Fact] void should_log_a_warning() => _deliveryLogger.Levels.ShouldContain(LogLevel.Warning);
    [Fact] void should_describe_the_signing_decision() => _deliveryLogger.Text.ShouldContain("could not be signed");
}
