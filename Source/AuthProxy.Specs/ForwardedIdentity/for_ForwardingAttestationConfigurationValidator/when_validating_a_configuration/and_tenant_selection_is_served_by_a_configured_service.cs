// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The tenant endpoint usually lives on one of the services, and then that service's audience is the one to sign for.
/// </summary>
public class and_tenant_selection_is_served_by_a_configured_service : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(WithTenantSelection(Configuration(signingKeys: P256Key("current")), "https://studio.internal/api/tenants", services: ("studio", "https://studio.internal", null)));

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
