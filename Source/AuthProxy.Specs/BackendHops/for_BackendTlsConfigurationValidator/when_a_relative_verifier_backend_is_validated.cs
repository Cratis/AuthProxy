// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_a_relative_verifier_backend_is_validated : client_verifier_validation
{
    protected override string BackendUrl => "backend/path";
    protected override string VerificationPath => "verify";

    void Because() => Validate();

    [Fact] void should_return_a_validation_failure() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_backend_setting() => string.Join(';', _result.Failures!).ShouldContain("Cratis:AuthProxy:Services:app:Backend:BaseUrl must use HTTPS");
}
