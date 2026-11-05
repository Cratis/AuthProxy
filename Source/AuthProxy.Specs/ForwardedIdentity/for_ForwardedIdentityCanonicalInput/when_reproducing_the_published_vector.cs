// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_reproducing_the_published_vector : given.the_published_vector
{
    void Because() => Canonicalize();
    [Fact] void should_accept_the_request() => accepted.ShouldBeTrue();
    [Fact] void should_match_the_exact_canonical_bytes() => CanonicalText().ShouldEqual(ExpectedCanonical);
    [Fact] void should_match_the_published_mac() => mac.ShouldEqual(MacA);
    [Fact] void should_match_the_complete_envelope() => ForwardedIdentityEnvelope.Format("k1", "1700000000", NonceA, mac).ShouldEqual(Envelope);
}
