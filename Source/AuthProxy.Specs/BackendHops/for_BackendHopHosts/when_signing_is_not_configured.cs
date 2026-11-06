// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendHopHosts;

public class when_signing_is_not_configured : Specification
{
    IReadOnlySet<string> _hosts;

    void Because() => _hosts = BackendHopHosts.For(new()
    {
        Invite = new() { StageUrl = "https://stage.example/stage", ExchangeUrl = "https://invite.example/exchange" },
        Link = new() { ExchangeUrl = "https://link.example/exchange" },
        SignIn = new() { NotifyUrl = "https://notify.example/notify" }
    });

    [Fact] void should_exclude_invitation_staging() => _hosts.Contains("stage.example").ShouldBeFalse();
    [Fact] void should_exclude_invitation_exchange() => _hosts.Contains("invite.example").ShouldBeFalse();
    [Fact] void should_exclude_link_exchange() => _hosts.Contains("link.example").ShouldBeFalse();
    [Fact] void should_exclude_sign_in_notification() => _hosts.Contains("notify.example").ShouldBeFalse();
}
