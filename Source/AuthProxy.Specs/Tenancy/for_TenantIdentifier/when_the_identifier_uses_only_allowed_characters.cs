// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantIdentifier;

public class when_the_identifier_uses_only_allowed_characters : Specification
{
    [Fact] void should_accept_letters_digits_and_punctuation() => TenantIdentifier.IsUsable("Acme-1_2.3~x").ShouldBeTrue();
    [Fact] void should_accept_a_guid() => TenantIdentifier.IsUsable(Guid.NewGuid().ToString()).ShouldBeTrue();
    [Fact] void should_accept_the_maximum_length() => TenantIdentifier.IsUsable(new string('a', TenantIdentifier.MaximumLength)).ShouldBeTrue();
}
