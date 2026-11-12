// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionStart;

public class when_stamping_at_sign_in : Specification
{
    AuthenticationProperties _properties;
    DateTimeOffset _time;
    bool _read;

    void Establish() => _properties = new AuthenticationProperties(new Dictionary<string, string?> { [SessionStart.PropertyKey] = "untrusted" });
    void Because()
    {
        SessionStart.Stamp(_properties, DateTimeOffset.FromUnixTimeSeconds(1700000000));
        _read = SessionStart.TryRead(_properties, out _time);
    }

    [Fact] void should_overwrite_the_incoming_property() => _properties.Items[SessionStart.PropertyKey].ShouldEqual("1700000000");
    [Fact] void should_read_the_protected_start() => _read.ShouldBeTrue();
    [Fact] void should_round_trip_the_sign_in_time() => _time.ShouldEqual(DateTimeOffset.FromUnixTimeSeconds(1700000000));
}
