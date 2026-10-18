// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// Startup validation rejects this shape; the signer still fails closed if it is ever handed one, rather than sending
/// the request unsigned.
/// </summary>
public class and_the_active_key_is_not_configured : a_forwarded_identity_signer
{
    HttpRequestMessage _request;
    ForwardedIdentitySigningStatus _status;

    void Establish() => _request = Request(headers: [(Headers.PrincipalId, Subject)]);

    void Because() => _status = _signer.Sign(_request, "reports");

    [Fact] void should_report_signing_as_enabled() => _signer.IsEnabled.ShouldBeTrue();
    [Fact] void should_report_the_signing_failed() => _status.ShouldEqual(ForwardedIdentitySigningStatus.Failed);
    [Fact] void should_add_no_assertion() => _request.Headers.Contains(Headers.ForwardedIdentity).ShouldBeFalse();

    protected override C.ForwardingAttestation? Attestation(string privateKeyPem)
    {
        var attestation = base.Attestation(privateKeyPem)!;
        attestation.ActiveKeyId = "next";
        return attestation;
    }
}
