// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The tenant-selection call is signed like any other, so it needs an audience. When no configured service serves the
/// endpoint and none is stated, startup fails rather than the call being sent unsigned.
/// </summary>
public class and_tenant_selection_is_served_by_no_service : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _unresolved;
    ValidateOptionsResult _stated;

    void Because()
    {
        _unresolved = Validate(WithTenantSelection(Configuration(signingKeys: P256Key("current")), "https://tenants.example.com/api/tenants", services: ("reports", "https://reports.internal", null)));
        _stated = Validate(WithTenantSelection(Configuration(signingKeys: P256Key("current")), "https://tenants.example.com/api/tenants", "tenants", ("reports", "https://reports.internal", null)));
    }

    [Fact] void should_reject_the_configuration_without_an_audience() => _unresolved.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_the_configuration_with_a_stated_audience() => _stated.Succeeded.ShouldBeTrue();
}
