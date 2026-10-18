// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// The signer never throws; every way a configured signer can fail comes back as a failure the caller must act on by
/// not sending the request.
/// </summary>
public class and_the_request_cannot_be_signed : a_forwarded_identity_signer
{
    HttpRequestMessage _relative;
    HttpRequestMessage _withoutAudience;
    ForwardedIdentitySigningStatus _relativeStatus;
    ForwardedIdentitySigningStatus _withoutAudienceStatus;

    void Establish()
    {
        _relative = new HttpRequestMessage(HttpMethod.Get, "/api/reports");
        _withoutAudience = Request();
    }

    void Because()
    {
        _relativeStatus = _signer.Sign(_relative, "reports");
        _withoutAudienceStatus = _signer.Sign(_withoutAudience, " ");
    }

    [Fact] void should_refuse_a_request_without_an_absolute_address() => _relativeStatus.ShouldEqual(ForwardedIdentitySigningStatus.Failed);
    [Fact] void should_refuse_a_request_without_an_audience() => _withoutAudienceStatus.ShouldEqual(ForwardedIdentitySigningStatus.Failed);
    [Fact] void should_add_no_assertion_without_an_audience() => _withoutAudience.Headers.Contains(Headers.ForwardedIdentity).ShouldBeFalse();
}
