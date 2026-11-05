// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_signing_is_disabled : given.a_signed_transport
{
    Task Because() => Send(configured: false);
    [Fact] void should_send_the_legacy_request() => transport.Calls.ShouldEqual(1);
    [Fact] void should_not_add_a_proof() => proof.ShouldBeNull();
}
