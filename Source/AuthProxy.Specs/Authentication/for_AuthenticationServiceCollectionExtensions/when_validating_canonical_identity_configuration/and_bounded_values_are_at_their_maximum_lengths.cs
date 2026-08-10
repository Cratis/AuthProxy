// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_canonical_identity_configuration;

/// <summary>
/// Specifies that canonical provider keys and subject claim types at their maximum lengths remain valid.
/// </summary>
public class and_bounded_values_are_at_their_maximum_lengths : given.canonical_configuration_validation
{
    IServiceProvider _services = null!;
    Exception? _exception;

    void Establish() => _services = BuildServices(ValidOidcProvider(
        providerKey: new string('a', 64),
        subjectClaimType: new string('s', 256)));

    void Because() => _exception = ResolveAuthenticationOptions(_services);

    [Fact] void should_pass_configuration_validation() => _exception.ShouldBeNull();
}
