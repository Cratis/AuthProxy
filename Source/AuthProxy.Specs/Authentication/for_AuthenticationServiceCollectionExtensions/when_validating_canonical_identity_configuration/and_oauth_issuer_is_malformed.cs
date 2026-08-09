// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_canonical_identity_configuration;

/// <summary>
/// Specifies that a malformed OAuth canonical issuer is rejected.
/// </summary>
public class and_oauth_issuer_is_malformed : given.canonical_configuration_validation
{
    IServiceProvider _services = null!;
    Exception? _exception;

    void Establish() => _services = BuildServices(ValidOAuthProvider(issuer: "not an issuer"));
    void Because() => _exception = ResolveAuthenticationOptions(_services);

    [Fact] void should_fail_configuration_validation() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
