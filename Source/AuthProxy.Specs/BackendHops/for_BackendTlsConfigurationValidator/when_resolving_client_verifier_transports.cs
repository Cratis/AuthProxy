// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_resolving_client_verifier_transports : Specification
{
    const string EndpointKey = "Cratis:AuthProxy:Services:client:ClientCredentials:VerificationPath must use HTTPS";
    ValidateOptionsResult _relativeHttp;
    ValidateOptionsResult _absoluteHttps;
    ValidateOptionsResult _localHttp;

    void Because()
    {
        _relativeHttp = Validate("http://backend.example", "verify", C.DeploymentProfile.Default);
        _absoluteHttps = Validate("http://backend.example", "https://verifier.example/verify", C.DeploymentProfile.Default);
        _localHttp = Validate("https://backend.example", "http://localhost/verify", C.DeploymentProfile.LocalDevelopment);
    }

    [Fact] void should_check_the_resolved_backend_relative_endpoint() => string.Join(';', _relativeHttp.Failures!).ShouldContain(EndpointKey);
    [Fact] void should_allow_an_absolute_https_endpoint() => string.Join(';', _absoluteHttps.Failures!).ShouldNotContain(EndpointKey);
    [Fact] void should_require_https_for_the_backend_even_with_an_absolute_verifier_endpoint() => string.Join(';', _absoluteHttps.Failures!).ShouldContain("Cratis:AuthProxy:Services:client:Backend:BaseUrl must use HTTPS");
    [Fact] void should_preserve_local_development_http() => _localHttp.Succeeded.ShouldBeTrue();

    static ValidateOptionsResult Validate(string backend, string endpoint, C.DeploymentProfile profile) => new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, new()
    {
        Profile = profile,
        Services = new Dictionary<string, C.Service>
        {
            ["signed"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() },
            ["client"] = new() { Backend = new() { BaseUrl = backend }, ClientCredentials = new() { VerificationPath = endpoint } }
        }
    });
}
