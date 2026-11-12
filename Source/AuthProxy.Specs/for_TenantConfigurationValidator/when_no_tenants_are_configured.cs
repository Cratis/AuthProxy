// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantConfigurationValidator;

public class when_no_tenants_are_configured : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new TenantConfigurationValidator().Validate(null, new C.AuthProxy());

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
