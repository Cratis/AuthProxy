// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_an_absolute_http_verifier_uses_an_https_backend : client_verifier_validation
{
    protected override string VerificationPath => "http://verifier.example/verify";

    void Because() => Validate();

    [Fact] void should_refuse_the_http_endpoint() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_endpoint_setting() => string.Join(';', _result.Failures!).ShouldContain("Cratis:AuthProxy:Services:app:ClientCredentials:VerificationPath must use HTTPS");
}
