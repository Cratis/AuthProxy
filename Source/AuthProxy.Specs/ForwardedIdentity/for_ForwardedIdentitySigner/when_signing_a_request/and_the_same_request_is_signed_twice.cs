// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;
using Cratis.AuthProxy.ForwardedIdentity.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// Every request gets a fresh assertion, so a verifier that keeps a replay cache never sees one identifier twice, and
/// re-signing a request replaces its assertion rather than sending two. The pooled key is reused across signatures.
/// </summary>
public class and_the_same_request_is_signed_twice : a_forwarded_identity_signer
{
    HttpRequestMessage _request;
    Assertion _first;
    Assertion _second;
    ForwardedIdentitySigningStatus _secondStatus;

    void Establish() => _request = Request(headers: [(Headers.PrincipalId, Subject)]);

    void Because()
    {
        _signer.Sign(_request, "reports");
        _first = Assertion.Parse(AssertionOf(_request));
        _secondStatus = _signer.Sign(_request, "reports");
        _second = Assertion.Parse(AssertionOf(_request));
    }

    [Fact] void should_sign_it_again() => _secondStatus.ShouldEqual(ForwardedIdentitySigningStatus.Attested);
    [Fact] void should_use_a_fresh_identifier() => _second.Text("jti").ShouldNotEqual(_first.Text("jti"));
    [Fact] void should_carry_one_assertion() => _request.Headers.GetValues(Headers.ForwardedIdentity).Count().ShouldEqual(1);
    [Fact] void should_verify_the_second_assertion() => _second.VerifiesWith(_publicKeyPem).ShouldBeTrue();
}
