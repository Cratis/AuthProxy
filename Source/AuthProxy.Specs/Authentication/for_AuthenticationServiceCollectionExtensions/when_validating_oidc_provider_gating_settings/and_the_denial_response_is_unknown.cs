// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_oidc_provider_gating_settings;

/// <summary>
/// Specifies that a numeric denial response outside the defined values does not silently mean the default.
/// </summary>
public class and_the_denial_response_is_unknown : given.canonical_configuration_validation
{
    ValidateOptionsResult _result = null!;

    void Because() => _result = new OidcAuthorizationParametersConfigurationValidator().Validate(
        null,
        new C.Authentication { OidcProviders = [new C.OidcProvider { Name = "Workforce", DenialResponse = (C.OidcDenialResponse)7 }] });

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_provider() => _result.FailureMessage.ShouldContain("Workforce");
}
