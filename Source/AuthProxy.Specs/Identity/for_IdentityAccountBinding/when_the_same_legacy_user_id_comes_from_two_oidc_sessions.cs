// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that two OIDC sessions sharing an identity provider name but signed in through different schemes get different bindings.
/// </summary>
public class when_the_same_legacy_user_id_comes_from_two_oidc_sessions : Specification
{
    IdentityAccountBinding _first;
    IdentityAccountBinding _second;

    void Because()
    {
        IdentityAccountBinding.TryCreate(new ClientPrincipal { IdentityProvider = "AuthenticationTypes.Federation", AccountProvider = "microsoft", UserId = "user-42" }, 2, out _first);
        IdentityAccountBinding.TryCreate(new ClientPrincipal { IdentityProvider = "AuthenticationTypes.Federation", AccountProvider = "google", UserId = "user-42" }, 2, out _second);
    }

    [Fact] void should_not_produce_equal_bindings() => _first.ShouldNotEqual(_second);
    [Fact] void should_carry_the_first_scheme() => _first.ProviderKey.ShouldEqual("microsoft");
    [Fact] void should_carry_the_second_scheme() => _second.ProviderKey.ShouldEqual("google");
}
