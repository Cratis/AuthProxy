// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// A bound header carried twice is read by the backend as one joined value, which is not what the digest would cover.
/// The signer refuses rather than sign something the backend will read differently.
/// </summary>
public class and_a_bound_header_is_repeated : a_forwarded_identity_signer
{
    HttpRequestMessage _request;
    ForwardedIdentitySigningStatus _status;

    void Establish() => _request = Request(headers: [(Headers.PrincipalId, Subject), (Headers.PrincipalId, "someone-else")]);

    void Because() => _status = _signer.Sign(_request, "reports");

    [Fact] void should_report_the_signing_failed() => _status.ShouldEqual(ForwardedIdentitySigningStatus.Failed);
    [Fact] void should_add_no_assertion() => _request.Headers.Contains(Headers.ForwardedIdentity).ShouldBeFalse();
}
