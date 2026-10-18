// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// Two services behind one origin with different audiences leave no single right answer, so the deployer has to state
/// one.
/// </summary>
public class and_tenant_selection_is_served_by_services_that_disagree : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _ambiguous;
    ValidateOptionsResult _settled;

    void Because()
    {
        _ambiguous = Validate(WithTenantSelection(
            Configuration(signingKeys: P256Key("current")),
            "https://shared.internal/api/tenants",
            services: [("studio", "https://shared.internal", null), ("reports", "https://shared.internal", null)]));
        _settled = Validate(WithTenantSelection(
            Configuration(signingKeys: P256Key("current")),
            "https://shared.internal/api/tenants",
            "studio",
            ("studio", "https://shared.internal", null),
            ("reports", "https://shared.internal", null)));
    }

    [Fact] void should_reject_the_ambiguous_configuration() => _ambiguous.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_the_configuration_once_an_audience_is_stated() => _settled.Succeeded.ShouldBeTrue();
}
