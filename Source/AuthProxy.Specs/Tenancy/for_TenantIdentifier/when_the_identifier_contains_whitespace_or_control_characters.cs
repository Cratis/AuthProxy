// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantIdentifier;

public class when_the_identifier_contains_whitespace_or_control_characters : Specification
{
    [Fact] void should_reject_a_space() => TenantIdentifier.IsUsable("a b").ShouldBeFalse();
    [Fact] void should_reject_a_line_break() => TenantIdentifier.IsUsable("a\r\nb").ShouldBeFalse();
    [Fact] void should_reject_a_tab() => TenantIdentifier.IsUsable("a\tb").ShouldBeFalse();
    [Fact] void should_reject_a_null_character() => TenantIdentifier.IsUsable("a\0b").ShouldBeFalse();
}
