// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// An exception while signing is an outcome that cannot be classified, so it is a failure, never a request sent
/// unsigned and never an exception escaping into the caller.
/// </summary>
public class and_the_signing_key_is_malformed : a_forwarded_identity_signer
{
    HttpRequestMessage _request;
    ForwardedIdentitySigningStatus _status;

    void Establish() => _request = Request(headers: [(Headers.PrincipalId, Subject)]);

    void Because() => _status = _signer.Sign(_request, "reports");

    [Fact] void should_report_the_signing_failed() => _status.ShouldEqual(ForwardedIdentitySigningStatus.Failed);
    [Fact] void should_add_no_assertion() => _request.Headers.Contains(Headers.ForwardedIdentity).ShouldBeFalse();

    protected override C.ForwardingAttestation? Attestation(string privateKeyPem) =>
        base.Attestation("-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----");
}
