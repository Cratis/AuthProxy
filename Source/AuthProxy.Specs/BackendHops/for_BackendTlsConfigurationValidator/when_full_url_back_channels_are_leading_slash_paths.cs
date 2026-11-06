// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_full_url_back_channels_are_leading_slash_paths : full_url_back_channels_validation
{
    protected override string Endpoint(string path) => path;

    void Because() => Validate();

    [Fact] void should_refuse_path_only_callback_and_on_behalf_backends() => Failures.ShouldContain("Services:app:Backend:BaseUrl must use HTTPS");
    [Fact] void should_refuse_path_only_invitation_staging() => Failures.ShouldContain("Invite:StageUrl must use HTTPS");
    [Fact] void should_refuse_path_only_invitation_exchange() => Failures.ShouldContain("Invite:ExchangeUrl must use HTTPS");
    [Fact] void should_refuse_path_only_link_exchange() => Failures.ShouldContain("Link:ExchangeUrl must use HTTPS");
    [Fact] void should_refuse_path_only_sign_in_notification() => Failures.ShouldContain("SignIn:NotifyUrl must use HTTPS");
    [Fact] void should_refuse_path_only_capability_verification() => Failures.ShouldContain("Admission:Capability:VerifierUrl must use HTTPS");
    [Fact] void should_refuse_path_only_tenant_verification() => Failures.ShouldContain("TenantVerification:UrlTemplate must use HTTPS");
    [Fact] void should_refuse_path_only_subhost_verification() => Failures.ShouldContain("TenantResolutions:0:Options:VerificationUrlTemplate must use HTTPS");

    string Failures => string.Join(';', _result.Failures!);
}
