// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// Unsigned forwarding is the default, so a deployment that does not sign is never refused for having no audience
/// to sign its tenant-selection call for.
/// </summary>
public class when_signing_is_not_configured : given.a_signing_deployment
{
    void Establish()
    {
        _configuration.ForwardingAttestation = null;
        SelectTenantsFrom("http://tenants-api:8080/api/tenants");
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
