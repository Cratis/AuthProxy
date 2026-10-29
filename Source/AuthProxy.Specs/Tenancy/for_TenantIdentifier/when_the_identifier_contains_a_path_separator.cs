// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantIdentifier;

public class when_the_identifier_contains_a_path_separator : Specification
{
    [Fact] void should_reject_a_slash() => TenantIdentifier.IsUsable("a/b").ShouldBeFalse();
    [Fact] void should_reject_an_encoded_slash() => TenantIdentifier.IsUsable("a%2Fb").ShouldBeFalse();
    [Fact] void should_reject_a_backslash() => TenantIdentifier.IsUsable("a\\b").ShouldBeFalse();
}
