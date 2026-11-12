// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_completed_sign_ins_record_a_session_start : configured_provider_sessions
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_replace_incoming_metadata_with_the_sign_in_time(bool oidc)
    {
        await using var services = Services(null, null);
        var properties = new AuthenticationProperties(new Dictionary<string, string?> { [SessionStart.PropertyKey] = "1" });
        var ticket = Ticket(services, oidc, properties);
        ((ClaimsIdentity)ticket.Principal!.Identity!).AddClaim(new Claim(SessionClaims.Started, "2"));
        await Receive(ticket);
        SessionStart.TryRead(properties, out var started).ShouldBeTrue();
        started.ShouldEqual(_clock.GetUtcNow());
        ticket.Principal.Claims.Any(_ => _.Type == SessionClaims.Started).ShouldBeFalse();
    }
}
