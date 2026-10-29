// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that a legacy principal without an identity provider still gets a binding when a single provider is configured.
/// </summary>
public class when_a_legacy_principal_has_no_provider_and_one_provider_is_configured : Specification
{
    bool _succeeded;
    IdentityAccountBinding _binding;

    void Because() => _succeeded = IdentityAccountBinding.TryCreate(new ClientPrincipal { IdentityProvider = string.Empty, UserId = "user-42" }, 1, out _binding);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_carry_the_user_identifier_as_the_subject() => _binding.Subject.ShouldEqual("user-42");
}
