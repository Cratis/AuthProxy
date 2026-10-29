// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAccountBinding;

/// <summary>
/// Specifies that a legacy principal without an identity provider has no reusable binding when several providers are configured.
/// </summary>
public class when_a_legacy_principal_has_no_provider_and_several_providers_are_configured : Specification
{
    bool _succeededWithNull;
    bool _succeededWithWhitespace;

    void Because()
    {
        _succeededWithNull = IdentityAccountBinding.TryCreate(new ClientPrincipal { IdentityProvider = null!, UserId = "user-42" }, 2, out _);
        _succeededWithWhitespace = IdentityAccountBinding.TryCreate(new ClientPrincipal { IdentityProvider = " ", UserId = "user-42" }, 2, out _);
    }

    [Fact] void should_not_produce_a_binding_for_a_null_provider() => _succeededWithNull.ShouldBeFalse();
    [Fact] void should_not_produce_a_binding_for_a_whitespace_provider() => _succeededWithWhitespace.ShouldBeFalse();
}
