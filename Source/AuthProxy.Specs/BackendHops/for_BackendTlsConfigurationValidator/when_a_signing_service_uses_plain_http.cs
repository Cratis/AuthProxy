// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_a_signing_service_uses_plain_http : Specification
{
    ValidateOptionsResult _result;
    void Because() => _result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, new()
    {
        Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "http://localhost" }, ForwardedIdentity = new() } }
    });

    [Fact] void should_refuse_startup() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_configuration_key() => string.Join(';', _result.Failures!).ShouldContain("Cratis:AuthProxy:Services:app:Backend:BaseUrl");
}
