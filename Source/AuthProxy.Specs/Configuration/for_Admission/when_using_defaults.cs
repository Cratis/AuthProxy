// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration.for_Admission;

/// <summary>
/// The defaults a deployment gets when it declares admission and says nothing else.
/// </summary>
/// <remarks>
/// The entry lifetime is the one with a reason outside itself: it has to outlast ASP.NET Core's own
/// fifteen-minute <c>RemoteAuthenticationTimeout</c>, because an entry that expires while the framework
/// still considers the handshake live returns the caller to the uniform refusal with nothing anywhere to
/// diagnose it from. The Aspire mirror pins the same number from the other side; without this the half that
/// actually runs in production could be moved back under that bound with every spec still green.
/// </remarks>
public class when_using_defaults : Specification
{
    Admission _admission;

    void Because() => _admission = new Admission();

    [Fact] void should_bound_the_entry_past_the_time_the_framework_allows_at_the_provider() => _admission.EntryLifetime.ShouldEqual(TimeSpan.FromMinutes(20));
}
