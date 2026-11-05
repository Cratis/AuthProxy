// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_an_uncovered_header_or_the_query_changes : given.the_published_vector
{
    void Establish()
    {
        request.RequestUri = new("http://backend.example/base/a%2fb?x=2");
        request.Headers.Add("Accept", "application/json");
    }
    void Because() => Canonicalize();
    [Fact] void should_not_bind_the_query_or_uncovered_headers() => mac.ShouldEqual(MacA);
}
