// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_only_partial_identity_is_present : given.a_signed_transport
{
    void Establish()
    {
        request.Headers.Clear();
        request.Headers.Add("x-ms-client-principal-extra", "identity-material");
    }
    Task Because() => Send();
    [Fact] void should_not_downgrade_to_anonymous() => transport.Calls.ShouldEqual(0);
    [Fact] void should_fail_closed() => exception.ShouldBeOfExactType<ForwardedIdentityCouldNotBeSigned>();
}
