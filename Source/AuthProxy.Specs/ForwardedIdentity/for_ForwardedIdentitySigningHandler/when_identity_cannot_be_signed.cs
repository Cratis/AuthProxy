// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_identity_cannot_be_signed : given.a_signed_transport
{
    void Establish() => request.Headers.TryAddWithoutValidation(Headers.PrincipalId, "user");
    Task Because() => Send();
    [Fact] void should_not_contact_the_backend() => transport.Calls.ShouldEqual(0);
    [Fact] void should_report_a_typed_failure() => exception.ShouldBeOfExactType<ForwardedIdentityCouldNotBeSigned>();
    [Fact] void should_not_attach_a_proof() => request.Headers.Contains(Headers.ForwardedIdentitySignature).ShouldBeFalse();
}
