// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;
using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_resolving_legacy_identity_details.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_resolving_legacy_identity_details;

/// <summary>
/// Specifies that two legacy principals with a blank user identifier do not share a cached identity result.
/// </summary>
/// <remarks>
/// This is the confirmed cross-user leak the binding-level guard closes: without it, both principals bound
/// to the same empty legacy key and the second caller was handed the first caller's cached identity.
/// </remarks>
public class with_two_blank_user_ids : a_legacy_identity_details_resolver
{
    IdentityProviderResult _first;
    IdentityProviderResult _second;

    async Task Because()
    {
        _first = await _resolver.Resolve(new DefaultHttpContext(), LegacyPrincipal(string.Empty), TenantId);
        _second = await _resolver.Resolve(new DefaultHttpContext(), LegacyPrincipal(string.Empty), TenantId);
    }

    [Fact] void should_call_the_identity_endpoint_for_each_request() => _handler.Calls.ShouldEqual(2);
    [Fact] void should_not_reuse_the_first_result() => ReferenceEquals(_first, _second).ShouldBeFalse();
}
