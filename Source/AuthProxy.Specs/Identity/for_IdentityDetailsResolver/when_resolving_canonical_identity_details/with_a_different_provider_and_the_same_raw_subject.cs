// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;
using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_resolving_canonical_identity_details;

/// <summary>
/// Specifies that two providers asserting the same raw subject do not share an identity result.
/// </summary>
public class with_a_different_provider_and_the_same_raw_subject : a_canonical_identity_details_resolver
{
    IdentityProviderResult _first;
    IdentityProviderResult _second;

    async Task Because()
    {
        _first = await _resolver.Resolve(new DefaultHttpContext(), Principal("workforce-a", "https://identity-a.example.com"), TenantId);
        _second = await _resolver.Resolve(new DefaultHttpContext(), Principal("workforce-b", "https://identity-b.example.com"), TenantId);
    }

    [Fact] void should_call_the_identity_endpoint_for_each_tuple() => _handler.Calls.ShouldEqual(2);
    [Fact] void should_not_reuse_the_first_result() => ReferenceEquals(_first, _second).ShouldBeFalse();
}
