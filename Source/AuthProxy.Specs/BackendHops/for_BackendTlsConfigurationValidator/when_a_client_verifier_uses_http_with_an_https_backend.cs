// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_a_client_verifier_uses_http_with_an_https_backend : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, new()
    {
        Services = new Dictionary<string, C.Service>
        {
            ["signed"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() },
            ["client"] = new() { Backend = new() { BaseUrl = "https://backend.example" }, ClientCredentials = new() { VerificationPath = "http://verifier.example/verify" } }
        }
    });

    [Fact] void should_refuse_the_verifier_transport() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_actual_endpoint_setting() => string.Join(';', _result.Failures!).ShouldContain("Cratis:AuthProxy:Services:client:ClientCredentials:VerificationPath must use HTTPS");
    [Fact] void should_not_blame_the_https_backend() => string.Join(';', _result.Failures!).ShouldNotContain("Cratis:AuthProxy:Services:client:Backend:BaseUrl must use HTTPS");
}
