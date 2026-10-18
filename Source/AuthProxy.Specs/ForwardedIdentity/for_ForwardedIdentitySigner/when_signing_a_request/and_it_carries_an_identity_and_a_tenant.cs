// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;
using Cratis.AuthProxy.ForwardedIdentity.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// The verifier lives in another repository and checks every byte of this, so the assertion is pinned down claim by
/// claim: what is signed, in which order, and that the signature holds under the public half of the key.
/// </summary>
public class and_it_carries_an_identity_and_a_tenant : a_forwarded_identity_signer
{
    HttpRequestMessage _request;
    ForwardedIdentitySigningStatus _status;
    Assertion _assertion;
    string _canonical;

    void Establish()
    {
        _request = Request(
            headers:
            [
                (Headers.TenantId, Tenant),
                (Headers.PrincipalName, "ada@example.com"),
                (Headers.PrincipalId, Subject),
                (Headers.Principal, "eyJjbGFpbXMiOltdfQ=="),
                ("accept", "application/json"),
            ]);
        _canonical = $"{Headers.Principal}:eyJjbGFpbXMiOltdfQ==\n{Headers.PrincipalId}:{Subject}\n{Headers.PrincipalName}:ada@example.com\n{Headers.TenantId}:{Tenant}\n";
    }

    void Because()
    {
        _status = _signer.Sign(_request, "reports");
        _assertion = Assertion.Parse(AssertionOf(_request));
    }

    [Fact] void should_report_the_request_signed() => _status.ShouldEqual(ForwardedIdentitySigningStatus.Attested);
    [Fact] void should_report_signing_as_enabled() => _signer.IsEnabled.ShouldBeTrue();
    [Fact] void should_write_the_exact_jose_header() => _assertion.ProtectedHeader.ShouldEqual("{\"alg\":\"ES256\",\"typ\":\"cratis-fwd+jwt\",\"kid\":\"current\"}");
    [Fact] void should_write_the_claims_in_the_contract_order() => string.Join(',', _assertion.ClaimNames).ShouldEqual("iss,aud,iat,nbf,exp,jti,htm,htp,sub,tid,fwh");
    [Fact] void should_write_no_whitespace_in_the_claims() => _assertion.Payload.Any(char.IsWhiteSpace).ShouldBeFalse();
    [Fact] void should_name_the_issuer() => _assertion.Text("iss").ShouldEqual(Issuer);
    [Fact] void should_name_the_audience() => _assertion.Text("aud").ShouldEqual("reports");
    [Fact] void should_be_issued_now() => _assertion.Number("iat").ShouldEqual(Now.ToUnixTimeSeconds());
    [Fact] void should_not_be_valid_before_now() => _assertion.Number("nbf").ShouldEqual(Now.ToUnixTimeSeconds());
    [Fact] void should_expire_after_the_default_lifetime() => _assertion.Number("exp").ShouldEqual(Now.ToUnixTimeSeconds() + 30);
    [Fact] void should_carry_a_128_bit_identifier() => Base64Url.DecodeFromChars(_assertion.Text("jti")).Length.ShouldEqual(16);
    [Fact] void should_bind_the_method() => _assertion.Text("htm").ShouldEqual("POST");
    [Fact] void should_bind_the_path_without_the_query() => _assertion.Text("htp").ShouldEqual("/api/reports/42");
    [Fact] void should_name_the_subject() => _assertion.Text("sub").ShouldEqual(Subject);
    [Fact] void should_name_the_tenant() => _assertion.Text("tid").ShouldEqual(Tenant);
    [Fact] void should_digest_the_bound_headers_in_contract_order() => _assertion.Text("fwh").ShouldEqual(ForwardedIdentityToken.Digest(_canonical));
    [Fact] void should_verify_with_the_public_key() => _assertion.VerifiesWith(_publicKeyPem).ShouldBeTrue();
    [Fact] void should_sign_with_a_64_byte_p1363_signature() => _assertion.Signature.Length.ShouldEqual(64);
}
