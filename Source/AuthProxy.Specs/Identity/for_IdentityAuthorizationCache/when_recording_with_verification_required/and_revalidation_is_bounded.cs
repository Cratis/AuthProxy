// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_recording_with_verification_required;

/// <summary>
/// The counterpart to a disabled interval: a deployment that does state a bound still gets the record, and
/// gets it bounded to exactly what it asked for. Refusing to record whenever verification is required would
/// put a fan-out of backend calls in front of every proxied request, which is not what "no bound" asked for
/// either.
/// </summary>
public class and_revalidation_is_bounded : given.a_verifying_deployment
{
    void Establish() => _configuration.Session.IdentityRevalidationInterval = TimeSpan.FromMinutes(2);

    void Because() => _cache.Record(_context, new ClientPrincipal { UserId = "user-1" }, TenantId);

    [Fact] void should_record_a_positive() => RecordWasWritten().ShouldBeTrue();
    [Fact] void should_bound_it_to_the_configured_interval() => _context.Response.Headers.SetCookie.ToString().ShouldContain("max-age=120");
}
