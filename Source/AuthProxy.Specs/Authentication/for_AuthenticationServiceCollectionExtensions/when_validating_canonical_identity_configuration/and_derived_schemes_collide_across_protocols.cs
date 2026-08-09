// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_canonical_identity_configuration;

/// <summary>
/// Specifies that case-normalized provider names cannot derive the same authentication scheme across protocols.
/// </summary>
public class and_derived_schemes_collide_across_protocols : given.canonical_configuration_validation
{
    IServiceProvider _services = null!;
    Exception? _exception;

    void Establish() => _services = BuildServices(Configuration(
        ValidOidcProvider(name: "Work Force"),
        ValidOAuthProvider(name: "WORK FORCE")));

    void Because() => _exception = ResolveAuthenticationOptions(_services);

    [Fact] void should_fail_configuration_validation() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
