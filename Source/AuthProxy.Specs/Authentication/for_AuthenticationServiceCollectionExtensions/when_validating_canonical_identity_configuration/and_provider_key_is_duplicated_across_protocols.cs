// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_canonical_identity_configuration;

/// <summary>
/// Specifies that a canonical provider key cannot be shared by OIDC and OAuth registrations.
/// </summary>
public class and_provider_key_is_duplicated_across_protocols : given.canonical_configuration_validation
{
    IServiceProvider _services = null!;
    Exception? _exception;

    void Establish() => _services = BuildServices(Configuration(
        ValidOidcProvider(providerKey: "workforce"),
        ValidOAuthProvider(providerKey: "workforce")));

    void Because() => _exception = ResolveAuthenticationOptions(_services);

    [Fact] void should_fail_configuration_validation() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
