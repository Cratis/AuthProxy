// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// The in-memory result cache is the window in which a revoked user still gets through, and it used to be a
/// hard-coded thirty seconds with no way to shorten it. Set to zero it must genuinely mean "ask every
/// time" — the second identical request re-verifies rather than being answered from memory.
/// </summary>
public class and_result_caching_is_disabled : given.a_required_verification_resolver
{
    IdentityProviderResult _second;

    void Establish() => _config.Session.IdentityResultCacheDuration = TimeSpan.Zero;

    async Task Because()
    {
        await _resolver.Resolve(_context, Principal(), TenantId);
        _second = await _resolver.Resolve(new DefaultHttpContext(), Principal(), TenantId);
    }

    [Fact] void should_verify_every_request() => _handler.Calls.ShouldEqual(2);
    [Fact] void should_still_authorize_a_verified_caller() => _second.IsAuthorized.ShouldBeTrue();
}
