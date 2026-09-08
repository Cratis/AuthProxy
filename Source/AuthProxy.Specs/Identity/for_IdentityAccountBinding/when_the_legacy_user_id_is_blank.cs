// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that a legacy principal with an empty user identifier never becomes a reusable binding.
/// </summary>
/// <remarks>
/// IdentityDetailsResolver uses the binding as a shared memory-cache and per-account lock key. An empty
/// identifier is not a stable identity, so two different unidentifiable principals must never be able to
/// collide on the same key and be handed each other's cached result.
/// </remarks>
public class when_the_legacy_user_id_is_blank : Specification
{
    bool _succeeded;
    IdentityAccountBinding _binding;

    void Because() => _succeeded = IdentityAccountBinding.TryCreate(new ClientPrincipal { UserId = string.Empty }, out _binding);

    [Fact] void should_not_succeed() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_produce_a_binding() => _binding.ShouldBeNull();
}
