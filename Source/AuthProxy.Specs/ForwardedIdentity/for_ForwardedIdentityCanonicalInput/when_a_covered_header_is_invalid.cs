// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_a_covered_header_is_invalid : given.the_published_vector
{
    [Theory]
    [InlineData("a\tb")]
    [InlineData("a\r\nb")]
    [InlineData("\u00e9")]
    [InlineData("\u007f")]
    public void should_refuse_control_or_non_ascii_values(string value)
    {
        request.Headers.TryAddWithoutValidation("x-ms-client-principal-extra", value);
        Canonicalize();
        accepted.ShouldBeFalse();
        refusal.ShouldEqual(ForwardedIdentityRefusal.InvalidHeaderValue);
    }
    [Fact]
    void should_refuse_65_headers()
    {
        for (var index = 0; index < 62; index++) request.Headers.Add($"x-ms-client-principal-extra-{index}", "v");
        Canonicalize();
        accepted.ShouldBeFalse();
        refusal.ShouldEqual(ForwardedIdentityRefusal.TooManyHeaders);
    }
    [Fact]
    void should_refuse_an_oversized_canonical_input()
    {
        request.Headers.Add("x-ms-client-principal-extra", new string('x', 32768));
        Canonicalize();
        accepted.ShouldBeFalse();
        refusal.ShouldEqual(ForwardedIdentityRefusal.CanonicalTooLarge);
    }
    [Theory]
    [InlineData("x-ms-client-principal")]
    [InlineData("x-ms-client-principal-id")]
    [InlineData("x-ms-client-principal-name")]
    public void should_require_each_identity_field(string name)
    {
        request.Headers.Remove(name);
        Canonicalize();
        accepted.ShouldBeFalse();
        refusal.ShouldEqual(ForwardedIdentityRefusal.IncompleteIdentity);
    }
    [Fact]
    void should_refuse_lowercase_methods()
    {
        request.Method = new("post");
        Canonicalize();
        accepted.ShouldBeFalse();
        refusal.ShouldEqual(ForwardedIdentityRefusal.InvalidMethod);
    }
    [Theory]
    [InlineData("/a%zz")]
    [InlineData("/a%")]
    [InlineData("/a%2")]
    [InlineData("/a b")]
    [InlineData("/a#b")]
    public void should_refuse_malformed_raw_paths(string path) => ForwardedIdentityCanonicalInput.Path(path).ShouldBeNull();
}
