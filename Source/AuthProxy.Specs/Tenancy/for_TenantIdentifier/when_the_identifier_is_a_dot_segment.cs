// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantIdentifier;

public class when_the_identifier_is_a_dot_segment : Specification
{
    [Fact] void should_reject_a_single_dot() => TenantIdentifier.IsUsable(".").ShouldBeFalse();
    [Fact] void should_reject_two_dots() => TenantIdentifier.IsUsable("..").ShouldBeFalse();
}
