// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_reproducing_the_second_vector : given.the_published_vector
{
    void Because() => Canonicalize(NonceB);
    [Fact] void should_match_the_second_mac() => mac.ShouldEqual(MacB);
    [Fact] void should_match_the_second_envelope() => ForwardedIdentityEnvelope.Format("k1", "1700000000", NonceB, mac).ShouldEqual($"v1.k1.1700000000.{NonceB}.{MacB}");
}
