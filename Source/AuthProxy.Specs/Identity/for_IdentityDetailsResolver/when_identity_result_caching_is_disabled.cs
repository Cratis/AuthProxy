// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

/// <summary>
/// The proxy keeps a resolved identity result in its own memory so a page load's burst of requests costs one
/// round-trip rather than dozens. How long it keeps it used to be a constant in the source, which left a
/// deployment no way to shorten the window in which a user whose access has just been revoked still gets
/// through. Zero has to mean what it says: resolve every time.
/// </summary>
public class when_identity_result_caching_is_disabled : a_canonical_identity_details_resolver
{
    void Establish() => _configuration.Session.IdentityResultCacheDuration = TimeSpan.Zero;

    async Task Because()
    {
        await _resolver.Resolve(new DefaultHttpContext(), Principal("workforce-a", "https://identity-a.example.com"), TenantId);
        await _resolver.Resolve(new DefaultHttpContext(), Principal("workforce-a", "https://identity-a.example.com"), TenantId);
    }

    [Fact] void should_call_the_identity_endpoint_for_every_request() => _handler.Calls.ShouldEqual(2);
}
