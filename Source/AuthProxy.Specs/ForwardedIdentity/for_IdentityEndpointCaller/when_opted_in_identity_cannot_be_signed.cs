// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_IdentityEndpointCaller;

public class when_opted_in_identity_cannot_be_signed : Specification
{
    IdentityEndpointCaller _caller;
    IdentityVerificationOutcome _outcome;
    IHttpClientFactory _clients;

    void Establish()
    {
        _clients = Substitute.For<IHttpClientFactory>();
        var signer = Substitute.For<IForwardedIdentitySigner>();
        signer.Sign(Arg.Any<HttpRequestMessage>(), Arg.Any<ForwardedIdentitySigningTarget>()).Returns(ForwardedIdentitySigningOutcome.Refused);
        _caller = new(_clients, Substitute.For<ILogger<IdentityEndpointCaller>>(), signer);
    }

    async Task Because() => _outcome = await _caller.Call("app", "https://backend.example", new() { UserId = "u" }, "tenant", "spec-caller", TimeSpan.Zero, CancellationToken.None);

    [Fact] void should_not_create_a_transport_client() => _clients.DidNotReceive().CreateClient(Arg.Any<string>());
    [Fact] void should_return_a_typed_unavailable_reason() => _outcome.Reason.ShouldEqual(IdentityVerificationReason.ForwardedIdentityNotSigned);
    [Fact] void should_report_an_indeterminate_outcome() => _outcome.Status.ShouldEqual(IdentityVerificationStatus.Indeterminate);
}
