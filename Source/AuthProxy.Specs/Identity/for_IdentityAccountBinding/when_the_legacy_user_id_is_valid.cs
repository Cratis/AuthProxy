// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that a legacy principal with a real, trimmed user identifier still produces a reusable binding.
/// </summary>
public class when_the_legacy_user_id_is_valid : Specification
{
    bool _succeeded;
    IdentityAccountBinding _binding;

    void Because() => _succeeded = IdentityAccountBinding.TryCreate(new ClientPrincipal { IdentityProvider = "legacy-provider", UserId = "user-42" }, out _binding);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_not_be_canonical() => _binding.IsCanonical.ShouldBeFalse();
    [Fact] void should_carry_the_user_identifier_as_the_subject() => _binding.Subject.ShouldEqual("user-42");
}
