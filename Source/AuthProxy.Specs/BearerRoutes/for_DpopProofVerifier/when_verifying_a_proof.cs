// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_verifying_a_proof : given_a_signed_proof
{
    [Fact] public void should_accept_a_signed_bound_proof() => Verify().Status.ShouldEqual(DpopProofStatus.Valid);

    [Theory]
    [InlineData("htm", "GET")]
    [InlineData("htu", "https://other.example.test/mcp")]
    [InlineData("ath", "wrong")]
    [InlineData("jti", "")]
    [InlineData("iat", "2000000000")]
    public void should_refuse_wrong_claims(string claim, string value)
    {
        Payload[claim] = value;
        Verify().Status.ShouldEqual(DpopProofStatus.Invalid);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    public void should_refuse_non_asymmetric_algorithms(string algorithm)
    {
        Header["alg"] = algorithm;
        Verify().Status.ShouldEqual(DpopProofStatus.Invalid);
    }

    [Theory]
    [InlineData("d")]
    [InlineData("p")]
    [InlineData("q")]
    [InlineData("dp")]
    [InlineData("dq")]
    [InlineData("qi")]
    [InlineData("oth")]
    [InlineData("k")]
    public void should_refuse_private_key_material(string member)
    {
        ((Dictionary<string, object>)Header["jwk"])[member] = "synthetic-private-material";
        Verify().Status.ShouldEqual(DpopProofStatus.Invalid);
    }

    [Theory]
    [InlineData(300)]
    [InlineData(-31)]
    public void should_refuse_iat_outside_the_skew(int offset) => Verify(now: Now + offset).Status.ShouldEqual(DpopProofStatus.Invalid);

    [Fact]
    public void should_refuse_a_different_confirmation_key()
    {
        DpopProofVerifier.Verify(Proof(), new("POST", Target, Token, new string('A', 43), Now)).Status.ShouldEqual(DpopProofStatus.Invalid);
    }

    [Fact] public void should_refuse_oversized_proofs() => Verify(new string('A', 4097)).Status.ShouldEqual(DpopProofStatus.Invalid);
    [Fact] public void should_refuse_duplicate_header_names() => Verify(Proof(header: "{\"typ\":\"dpop+jwt\",\"typ\":\"dpop+jwt\"}")).Status.ShouldEqual(DpopProofStatus.Invalid);
    [Fact] public void should_refuse_duplicate_payload_names() => Verify(Proof(payload: "{\"jti\":\"a\",\"jti\":\"b\"}")).Status.ShouldEqual(DpopProofStatus.Invalid);
}
