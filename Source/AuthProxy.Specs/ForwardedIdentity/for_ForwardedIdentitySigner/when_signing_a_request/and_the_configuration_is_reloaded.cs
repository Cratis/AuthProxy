// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;
using Cratis.AuthProxy.ForwardedIdentity.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// Keys are loaded at startup and never reloaded, so a configuration reload cannot switch signing off underneath a
/// running deployment. Service audiences follow the current configuration, like the routes they belong to.
/// </summary>
public class and_the_configuration_is_reloaded : a_forwarded_identity_signer
{
    HttpRequestMessage _request;
    ForwardedIdentitySigningStatus _status;
    string _audience;

    void Establish()
    {
        _request = Request(headers: [(Headers.PrincipalId, Subject)]);
        _configuration = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service> { ["reports"] = new C.Service { ForwardingAudience = "reports-api" } },
        };
    }

    void Because()
    {
        _status = _signer.Sign(_request, "reports");
        _audience = _signer.AudienceFor("reports");
    }

    [Fact] void should_keep_signing_enabled() => _signer.IsEnabled.ShouldBeTrue();
    [Fact] void should_still_sign_the_request() => _status.ShouldEqual(ForwardedIdentitySigningStatus.Attested);
    [Fact] void should_still_sign_with_the_startup_key() => Assertion.Parse(AssertionOf(_request)).VerifiesWith(_publicKeyPem).ShouldBeTrue();
    [Fact] void should_follow_the_current_service_audience() => _audience.ShouldEqual("reports-api");
}
