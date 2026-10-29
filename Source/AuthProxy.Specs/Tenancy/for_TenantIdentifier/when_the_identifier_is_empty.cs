// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantIdentifier;

public class when_the_identifier_is_empty : Specification
{
    [Fact] void should_reject_an_empty_value() => TenantIdentifier.IsUsable(string.Empty).ShouldBeFalse();
    [Fact] void should_reject_a_missing_value() => TenantIdentifier.IsUsable(null).ShouldBeFalse();
}
