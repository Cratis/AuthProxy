// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_identity_back_channels_use_plain_http : identity_back_channels
{
    void Because() => _result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, _configuration);

    [Fact] void should_refuse_startup() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_callback_backend() => Failures.ShouldContain("Cratis:AuthProxy:Services:callbacks:Backend:BaseUrl");
    [Fact] void should_name_invitation_staging() => Failures.ShouldContain("Cratis:AuthProxy:Invite:StageUrl");
    [Fact] void should_name_invitation_exchange() => Failures.ShouldContain("Cratis:AuthProxy:Invite:ExchangeUrl");
    [Fact] void should_name_link_exchange() => Failures.ShouldContain("Cratis:AuthProxy:Link:ExchangeUrl");
    [Fact] void should_name_sign_in_notification() => Failures.ShouldContain("Cratis:AuthProxy:SignIn:NotifyUrl");
    [Fact] void should_name_capability_verification() => Failures.ShouldContain("Cratis:AuthProxy:Admission:Capability:VerifierUrl");
    [Fact] void should_name_tenant_verification() => Failures.ShouldContain("Cratis:AuthProxy:TenantVerification:UrlTemplate");
    [Fact] void should_name_subhost_verification() => Failures.ShouldContain("Cratis:AuthProxy:TenantResolutions:0:Options:VerificationUrlTemplate");

    string Failures => string.Join(';', _result.Failures!);
}
