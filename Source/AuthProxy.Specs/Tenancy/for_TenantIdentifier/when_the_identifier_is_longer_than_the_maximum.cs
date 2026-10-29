// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_TenantIdentifier;

public class when_the_identifier_is_longer_than_the_maximum : Specification
{
    [Fact] void should_reject_the_value() => TenantIdentifier.IsUsable(new string('a', TenantIdentifier.MaximumLength + 1)).ShouldBeFalse();
}
