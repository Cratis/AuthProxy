// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration.for_Session;

public class when_using_defaults : Specification
{
    Session _session;

    void Because() => _session = new Session();

    [Fact] void should_bound_the_session_lifetime_to_twelve_hours() => _session.Lifetime.ShouldEqual(TimeSpan.FromHours(12));
    [Fact] void should_use_an_absolute_lifetime() => _session.SlidingExpiration.ShouldBeFalse();
    [Fact] void should_preserve_the_session_on_identity_denial() => _session.TerminateOnIdentityDenial.ShouldBeFalse();
    [Fact] void should_revalidate_identity_every_ten_minutes() => _session.IdentityRevalidationInterval.ShouldEqual(TimeSpan.FromMinutes(10));
    [Fact] void should_revalidate_the_selected_tenant_every_ten_minutes() => _session.TenantRevalidationInterval.ShouldEqual(TimeSpan.FromMinutes(10));
}
