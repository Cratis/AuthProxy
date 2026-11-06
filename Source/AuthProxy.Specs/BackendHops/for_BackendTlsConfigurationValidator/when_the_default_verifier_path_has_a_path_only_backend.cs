// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_the_default_verifier_path_has_a_path_only_backend : client_verifier_validation
{
    protected override string BackendUrl => "/backend";

    void Because() => Validate();

    [Fact] void should_return_a_validation_failure() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_backend_setting() => string.Join(';', _result.Failures!).ShouldContain("Cratis:AuthProxy:Services:app:Backend:BaseUrl must use HTTPS");
}
