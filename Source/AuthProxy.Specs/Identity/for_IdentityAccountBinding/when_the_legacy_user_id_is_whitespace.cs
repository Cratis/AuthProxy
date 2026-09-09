// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that a legacy principal with a whitespace-only user identifier never becomes a reusable binding.
/// </summary>
/// <remarks>
/// Whitespace round-trips through <c language="text">IsNullOrWhiteSpace</c> checks that only look for an empty string, so it
/// is exactly the kind of value that used to slip through and become a shared cache/lock key for every
/// caller whose provider omitted a subject claim.
/// </remarks>
public class when_the_legacy_user_id_is_whitespace : Specification
{
    bool _succeeded;
    IdentityAccountBinding _binding;

    void Because() => _succeeded = IdentityAccountBinding.TryCreate(new ClientPrincipal { UserId = "   " }, out _binding);

    [Fact] void should_not_succeed() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_produce_a_binding() => _binding.ShouldBeNull();
}
