// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_a_covered_header_is_repeated : given.the_published_vector
{
    void Establish() => request.Headers.TryAddWithoutValidation(Headers.PrincipalId, "u");
    void Because() => Canonicalize();
    [Fact] void should_refuse_even_identical_values() => accepted.ShouldBeFalse();
    [Fact] void should_classify_the_refusal() => refusal.ShouldEqual(ForwardedIdentityRefusal.RepeatedHeader);
    [Fact] void should_not_emit_canonical_bytes() => canonical.ShouldBeEmpty();
}
