// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// Every deployment that has not opted in must start unaffected, including one whose tenant-selection endpoint no
/// service serves.
/// </summary>
public class and_signing_is_not_configured : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because()
    {
        var configuration = WithTenantSelection(new C.AuthProxy(), "https://tenants.example.com/api/tenants");
        _result = Validate(configuration);
    }

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
