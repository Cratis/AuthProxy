// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_the_service_is_signed : given.a_sender
{
    protected override ForwardedIdentitySigningOutcome SigningOutcome => ForwardedIdentitySigningOutcome.SignatureCreated;

    async Task Because() => _delivered = await _sender.Send(CreateRequest(), CancellationToken.None);

    [Fact] void should_deliver_the_callback() => _delivered.ShouldBeTrue();
    [Fact] void should_use_the_signed_client() => _factory.Received(1).CreateClient(ForwardedIdentityServiceCollectionExtensions.HttpClientName);
    [Fact] void should_sign_for_the_callback_service() => _signer.Received(1).Sign(Arg.Any<HttpRequestMessage>(), Arg.Is<ForwardedIdentitySigningTarget>(target => target.Flow == ForwardedIdentityFlow.SignInCallback && target.ServiceName == "app"));
}
