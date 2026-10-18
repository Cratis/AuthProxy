// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;
using Cratis.AuthProxy.ForwardedIdentity.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// Startup validation rejects a lifetime past the maximum, but the signer does not lean on that: whatever it was
/// given, an assertion never lives longer than the contract allows.
/// </summary>
public class and_the_configured_lifetime_is_out_of_bounds : a_forwarded_identity_signer
{
    HttpRequestMessage _request;
    Assertion _assertion;

    void Establish() => _request = Request();

    void Because()
    {
        _signer.Sign(_request, "reports");
        _assertion = Assertion.Parse(AssertionOf(_request));
    }

    [Fact] void should_cap_the_lifetime_at_the_maximum() => (_assertion.Number("exp") - _assertion.Number("iat")).ShouldEqual(60L);

    protected override C.ForwardingAttestation? Attestation(string privateKeyPem)
    {
        var attestation = base.Attestation(privateKeyPem)!;
        attestation.Lifetime = TimeSpan.FromMinutes(5);
        return attestation;
    }
}
