// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_tenants_are_resolved_by_sub_host_without_a_domain : given.a_session_validator
{
    void Establish() => _config.TenantResolutions = [new() { Strategy = C.TenantSourceIdentifierResolverType.SubHost }];

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
