// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_the_request_is_anonymous : given.a_signed_transport
{
    void Establish()
    {
        request.Headers.Clear();
        request.Headers.Add(Headers.TenantId, "tenant-only");
        request.Headers.Add(Headers.ForwardedIdentitySignature, "stale");
    }
    Task Because() => Send();
    [Fact] void should_forward_without_minting_identity() => transport.Calls.ShouldEqual(1);
    [Fact] void should_remove_a_stale_proof() => proof.ShouldBeNull();
}
