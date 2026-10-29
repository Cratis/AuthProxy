// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that a session recording no provider has no reusable binding when several providers are configured.
/// </summary>
public class when_a_legacy_session_has_no_recorded_provider_and_several_providers_are_configured : Specification
{
    bool _result;

    void Because() => _result = IdentityAccountBinding.TryCreate(
        new ClientPrincipal { IdentityProvider = "AuthenticationTypes.Federation", AccountProvider = string.Empty, UserId = "user-42" },
        2,
        out _);

    [Fact] void should_not_produce_a_binding() => _result.ShouldBeFalse();
}
