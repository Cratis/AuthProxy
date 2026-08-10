// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_canonical_identity_configuration;

/// <summary>
/// Specifies that distinct valid OIDC and OAuth canonical identity contracts pass together.
/// </summary>
public class and_distinct_oidc_and_oauth_contracts_are_valid : given.canonical_configuration_validation
{
    IServiceProvider _services = null!;
    Exception? _exception;

    void Establish() => _services = BuildServices(Configuration(ValidOidcProvider(), ValidOAuthProvider()));
    void Because() => _exception = ResolveAuthenticationOptions(_services);

    [Fact] void should_pass_configuration_validation() => _exception.ShouldBeNull();
}
