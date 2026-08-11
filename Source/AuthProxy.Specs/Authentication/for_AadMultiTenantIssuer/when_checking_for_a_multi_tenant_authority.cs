// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AadMultiTenantIssuer;

public class when_checking_for_a_multi_tenant_authority : Specification
{
    [Fact] void should_recognize_common() => AadMultiTenantIssuer.IsMultiTenantAuthority("https://login.microsoftonline.com/common/v2.0").ShouldBeTrue();
    [Fact] void should_recognize_organizations() => AadMultiTenantIssuer.IsMultiTenantAuthority("https://login.microsoftonline.com/organizations/v2.0").ShouldBeTrue();
    [Fact] void should_recognize_consumers() => AadMultiTenantIssuer.IsMultiTenantAuthority("https://login.microsoftonline.com/consumers/v2.0").ShouldBeTrue();
    [Fact] void should_not_treat_a_single_tenant_authority_as_multi_tenant() => AadMultiTenantIssuer.IsMultiTenantAuthority("https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0").ShouldBeFalse();
    [Fact] void should_not_treat_another_host_as_multi_tenant() => AadMultiTenantIssuer.IsMultiTenantAuthority("https://accounts.google.com").ShouldBeFalse();
    [Fact] void should_not_treat_a_missing_authority_as_multi_tenant() => AadMultiTenantIssuer.IsMultiTenantAuthority(null).ShouldBeFalse();
}
