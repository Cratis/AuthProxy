// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator;

public class when_it_is_set_on_the_lobby : given.a_validator
{
    void Because() => _result = Validate(new()
    {
        Invite = new() { Lobby = new() { Backend = new() { BaseUrl = "http://lobby/", StickyRouting = Sticky() } } },
    });

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_full_key() => _result.FailureMessage.ShouldContain("Cratis:AuthProxy:Invite:Lobby:Backend:StickyRouting");
}
