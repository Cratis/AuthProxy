// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_canonical_input_reaches_the_byte_limit : given.the_published_vector
{
    [Theory]
    [InlineData("arc-test")]
    [InlineData("audience-\u00e9")]
    public void should_preserve_the_exact_utf8_byte_boundary(string audience)
    {
        const string header = "x-ms-client-principal-extra";
        request.Headers.Add(header, "x");
        Canonicalize(audience: audience);
        accepted.ShouldBeTrue();
        var overhead = canonical.Length - Encoding.UTF8.GetByteCount("1:x\n");
        var value = new string('x', 32768 - overhead - 7);
        request.Headers.Remove(header);
        request.Headers.Add(header, value);
        Canonicalize(audience: audience);
        accepted.ShouldBeTrue();
        canonical.Length.ShouldEqual(32768);

        request.Headers.Remove(header);
        request.Headers.Add(header, value + "x");
        Canonicalize(audience: audience);
        accepted.ShouldBeFalse();
        refusal.ShouldEqual(ForwardedIdentityRefusal.CanonicalTooLarge);
        canonical.ShouldBeEmpty();
    }
}
