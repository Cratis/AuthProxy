// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_canonical_identity_configuration;

/// <summary>
/// Specifies that plain HTTP is rejected for a non-loopback OAuth canonical issuer.
/// </summary>
public class and_oauth_issuer_uses_non_loopback_http : given.canonical_configuration_validation
{
    IServiceProvider _services = null!;
    Exception? _exception;

    void Establish() => _services = BuildServices(ValidOAuthProvider(issuer: "http://identity.example.com"));
    void Because() => _exception = ResolveAuthenticationOptions(_services);

    [Fact] void should_fail_configuration_validation() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
