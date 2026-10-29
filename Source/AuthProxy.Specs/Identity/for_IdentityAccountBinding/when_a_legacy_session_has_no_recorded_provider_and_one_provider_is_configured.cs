// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that a session recording no provider keeps the binding released versions produced when one provider is configured.
/// </summary>
public class when_a_legacy_session_has_no_recorded_provider_and_one_provider_is_configured : Specification
{
    bool _result;
    IdentityAccountBinding _binding;

    void Because() => _result = IdentityAccountBinding.TryCreate(
        new ClientPrincipal { IdentityProvider = "AuthenticationTypes.Federation", AccountProvider = string.Empty, UserId = "user-42" },
        1,
        out _binding);

    [Fact] void should_produce_a_binding() => _result.ShouldBeTrue();
    [Fact] void should_have_no_provider_key() => _binding.ProviderKey.ShouldEqual(string.Empty);
}
