// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_tenants_are_resolved_by_sub_host_under_a_domain : given.a_session_validator
{
    void Establish()
    {
        _config.Session.CookieDomain = ".example.test";
        _config.TenantResolutions = [new() { Strategy = C.TenantSourceIdentifierResolverType.Claim }, new() { Strategy = C.TenantSourceIdentifierResolverType.SubHost }];
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_sub_host_strategy() => Reports("SubHost").ShouldBeTrue();
}
