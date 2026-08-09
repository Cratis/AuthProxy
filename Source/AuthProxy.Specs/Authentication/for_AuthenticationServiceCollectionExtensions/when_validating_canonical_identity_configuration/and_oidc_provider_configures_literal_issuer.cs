// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_canonical_identity_configuration;

/// <summary>
/// Specifies that an OIDC canonical identity cannot replace the framework-validated token issuer with configuration.
/// </summary>
public class and_oidc_provider_configures_literal_issuer : given.canonical_configuration_validation
{
    IServiceProvider _services = null!;
    Exception? _exception;

    void Establish() => _services = BuildServices(ValidOidcProvider(issuer: "https://identity.example.com"));
    void Because() => _exception = ResolveAuthenticationOptions(_services);

    [Fact] void should_fail_configuration_validation() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
