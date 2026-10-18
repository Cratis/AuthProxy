// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// Unsigned forwarding is the default, and a deployment that has not opted in must send exactly what it always sent.
/// </summary>
public class and_signing_is_not_configured : a_forwarded_identity_signer
{
    HttpRequestMessage _request;
    ForwardedIdentitySigningStatus _status;

    void Establish() => _request = Request(headers: [(Headers.PrincipalId, Subject)]);

    void Because() => _status = _signer.Sign(_request, "reports");

    [Fact] void should_report_signing_as_not_configured() => _status.ShouldEqual(ForwardedIdentitySigningStatus.NotConfigured);
    [Fact] void should_report_signing_as_disabled() => _signer.IsEnabled.ShouldBeFalse();
    [Fact] void should_add_no_assertion() => _request.Headers.Contains(Headers.ForwardedIdentity).ShouldBeFalse();
    [Fact] void should_leave_the_identity_untouched() => _request.Headers.GetValues(Headers.PrincipalId).Single().ShouldEqual(Subject);

    protected override C.ForwardingAttestation? Attestation(string privateKeyPem) => null;
}
