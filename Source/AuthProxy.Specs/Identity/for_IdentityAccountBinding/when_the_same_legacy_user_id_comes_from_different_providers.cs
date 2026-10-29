// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that legacy principals with the same user identifier from different identity providers get different bindings.
/// </summary>
public class when_the_same_legacy_user_id_comes_from_different_providers : Specification
{
    IdentityAccountBinding _first;
    IdentityAccountBinding _second;

    void Because()
    {
        IdentityAccountBinding.TryCreate(new ClientPrincipal { IdentityProvider = "provider-a", UserId = "user-42" }, 2, out _first);
        IdentityAccountBinding.TryCreate(new ClientPrincipal { IdentityProvider = "provider-b", UserId = "user-42" }, 2, out _second);
    }

    [Fact] void should_not_produce_equal_bindings() => _first.ShouldNotEqual(_second);
    [Fact] void should_carry_the_provider_of_the_first_principal() => _first.ProviderKey.ShouldEqual("provider-a");
    [Fact] void should_carry_the_provider_of_the_second_principal() => _second.ProviderKey.ShouldEqual("provider-b");
}
