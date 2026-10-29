// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantIdentifier;

public class when_the_identifier_contains_query_or_fragment_characters : Specification
{
    [Fact] void should_reject_a_query() => TenantIdentifier.IsUsable("a?x=1").ShouldBeFalse();
    [Fact] void should_reject_a_fragment() => TenantIdentifier.IsUsable("a#b").ShouldBeFalse();
}
