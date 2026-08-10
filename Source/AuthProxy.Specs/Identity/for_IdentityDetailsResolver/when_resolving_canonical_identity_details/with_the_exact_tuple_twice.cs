// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;
using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_resolving_canonical_identity_details;

/// <summary>
/// Specifies that the exact canonical tuple can reuse a memory-cached identity result.
/// </summary>
public class with_the_exact_tuple_twice : a_canonical_identity_details_resolver
{
    IdentityProviderResult _first;
    IdentityProviderResult _second;

    async Task Because()
    {
        var principal = Principal("workforce-a", "https://identity-a.example.com");
        _first = await _resolver.Resolve(new DefaultHttpContext(), principal, TenantId);
        _second = await _resolver.Resolve(new DefaultHttpContext(), principal, TenantId);
    }

    [Fact] void should_call_the_identity_endpoint_once() => _handler.Calls.ShouldEqual(1);
    [Fact] void should_reuse_the_result() => ReferenceEquals(_first, _second).ShouldBeTrue();
}
