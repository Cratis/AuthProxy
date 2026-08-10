// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AuthorizationConfigurationValidator;

/// <summary>
/// A usable configuration — and a configuration declaring nothing at all — start.
/// <para>
/// The empty case is the one worth pinning: this validator runs on every AuthProxy, including the great
/// majority that will never declare a requirement, and a validator that refused an absent section would
/// stop every one of them from starting.
/// </para>
/// </summary>
public class when_every_requirement_names_a_claim : Specification
{
    AuthorizationConfigurationValidator _validator;
    ValidateOptionsResult _declaringRequirements;
    ValidateOptionsResult _declaringNothing;

    void Establish() => _validator = new AuthorizationConfigurationValidator();

    void Because()
    {
        _declaringRequirements = _validator.Validate(null, new C.AuthProxy
        {
            Authorization = new C.Authorization
            {
                RequiredClaims = [new C.ClaimRequirement { Claim = "urn:github:organization", AnyOf = ["Cratis"] }],
            },
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" } },
            },
        });

        _declaringNothing = _validator.Validate(null, new C.AuthProxy());
    }

    [Fact] void should_accept_a_usable_configuration() => _declaringRequirements.Succeeded.ShouldBeTrue();
    [Fact] void should_accept_a_configuration_that_declares_nothing() => _declaringNothing.Succeeded.ShouldBeTrue();
}
