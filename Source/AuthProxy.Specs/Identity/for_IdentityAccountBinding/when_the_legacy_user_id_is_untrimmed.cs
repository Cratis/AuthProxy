// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that a legacy principal whose user identifier carries leading or trailing whitespace never
/// becomes a reusable binding.
/// </summary>
/// <remarks>
/// Silently trimming would let two differently-padded values that a naive comparison treats as the same
/// identity slip past unnoticed. Mirroring the canonical guard's own trimmed-value check, an untrimmed
/// identifier fails closed instead.
/// </remarks>
public class when_the_legacy_user_id_is_untrimmed : Specification
{
    bool _succeeded;
    IdentityAccountBinding _binding;

    void Because() => _succeeded = IdentityAccountBinding.TryCreate(new ClientPrincipal { UserId = " user-42 " }, out _binding);

    [Fact] void should_not_succeed() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_produce_a_binding() => _binding.ShouldBeNull();
}
