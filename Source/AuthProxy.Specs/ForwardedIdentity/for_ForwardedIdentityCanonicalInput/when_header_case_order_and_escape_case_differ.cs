// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_header_case_order_and_escape_case_differ : given.the_published_vector
{
    void Establish()
    {
        request.Headers.Clear();
        request.Headers.Add("X-MS-Client-Principal-Name", " \tn\t ");
        request.Headers.Add("X-MS-CLIENT-PRINCIPAL-ID", "u");
        request.Headers.Add("X-MS-CLIENT-PRINCIPAL", Principal);
        request.RequestUri = new("http://backend.example/base/a%2Fb?x=1");
    }
    void Because() => Canonicalize();
    [Fact] void should_have_the_same_canonical_input() => CanonicalText().ShouldEqual(ExpectedCanonical);
    [Fact] void should_have_the_same_mac() => mac.ShouldEqual(MacA);
}
