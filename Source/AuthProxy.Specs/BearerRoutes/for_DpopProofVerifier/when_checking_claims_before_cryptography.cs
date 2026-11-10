// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_checking_claims_before_cryptography : given_a_signed_proof
{
    [Theory]
    [InlineData("htm", "GET", "htm_mismatch")]
    [InlineData("htu", "https://other.example.test/mcp", "htu_mismatch")]
    [InlineData("iat", "old", "iat_outside_window")]
    public void should_reject_wrong_claims_before_an_invalid_key(string claim, string value, string reason)
    {
        Header["jwk"] = new { kty = "EC", crv = "P-256", x = Encode(new byte[32]), y = Encode(new byte[32]) };
        Payload[claim] = value;
        Verify().Reason.ShouldEqual(reason);
    }

    [Theory]
    [InlineData("typ", "wrong", "invalid_header")]
    [InlineData("alg", "none", "invalid_signature")]
    public void should_reject_wrong_header_before_an_invalid_key(string member, string value, string reason)
    {
        Header["jwk"] = new { kty = "EC", crv = "P-256", x = Encode(new byte[32]), y = Encode(new byte[32]) };
        Header[member] = value;
        Verify().Reason.ShouldEqual(reason);
    }

    [Fact]
    public void should_explicitly_refuse_an_off_curve_point()
    {
        Header["jwk"] = new { kty = "EC", crv = "P-256", x = Encode(new byte[32]), y = Encode(new byte[32]) };
        Verify().Reason.ShouldEqual("invalid_signature");
    }

    [Fact]
    public void should_keep_the_ext_member_refused()
    {
        ((Dictionary<string, object>)Header["jwk"])["ext"] = true;
        Verify().Reason.ShouldEqual("invalid_signature");
    }

    [Fact]
    public void should_keep_an_explicit_default_port_refused()
    {
        Payload["htu"] = "https://api.example.test:443/mcp";
        Verify().Reason.ShouldEqual("htu_mismatch");
    }
}
