// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionAuthenticationTime;

public class when_reading_session_time : Specification
{
    readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1700000000);

    [Theory]
    [InlineData(0, true)]
    [InlineData(300, true)]
    [InlineData(301, false)]
    [InlineData(-1, false)]
    public void should_require_matching_non_future_time_within_the_age(int age, bool fresh)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([], "session"));
        var properties = new AuthenticationProperties();
        SessionAuthenticationTime.Stamp(principal, properties, _now.AddSeconds(-age));
        SessionAuthenticationTime.IsFresh(principal, properties, TimeSpan.FromSeconds(300), _now).ShouldEqual(fresh);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("mismatch")]
    [InlineData("malformed")]
    public void should_refuse_untrusted_time(string kind)
    {
        var identity = new ClaimsIdentity([], "session");
        var principal = new ClaimsPrincipal(identity);
        var properties = new AuthenticationProperties();
        SessionAuthenticationTime.Stamp(principal, properties, _now);
        if (kind == "missing") properties.Items.Remove(SessionAuthenticationTime.PropertyKey);
        if (kind == "duplicate") identity.AddClaim(new Claim(SessionClaims.AuthenticationTime, _now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        if (kind == "mismatch") properties.Items[SessionAuthenticationTime.PropertyKey] = "1699999999";
        if (kind == "malformed") properties.Items[SessionAuthenticationTime.PropertyKey] = "today";
        SessionAuthenticationTime.IsFresh(principal, properties, TimeSpan.FromSeconds(300), _now).ShouldBeFalse();
    }

    [Fact]
    public void should_leave_provider_readable_with_or_without_time()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([], "session"));
        var properties = new AuthenticationProperties();
        SessionProvider.Stamp(principal, properties, "oidc");
        SessionProvider.TryRead(principal, properties, out _).ShouldBeTrue();
        SessionAuthenticationTime.Stamp(principal, properties, _now);
        SessionProvider.TryRead(principal, properties, out _).ShouldBeTrue();
        SessionProvider.Inspect(principal, properties).ShouldEqual(SessionProviderState.Recorded);
    }

    [Fact]
    public void should_strip_provider_supplied_time_and_reject_duplicate_provider()
    {
        var identity = new ClaimsIdentity([new Claim(SessionClaims.AuthenticationTime, "1700000000")], "session");
        var principal = new ClaimsPrincipal(identity);
        var properties = new AuthenticationProperties();
        SessionProvider.Stamp(principal, properties, "oidc");
        principal.HasClaim(claim => SessionClaims.IsReserved(claim.Type) && claim.Type != SessionClaims.ProviderScheme).ShouldBeFalse();
        SessionAuthenticationTime.Stamp(principal, properties, _now);
        identity.AddClaim(new Claim(SessionClaims.ProviderScheme, "oidc"));
        SessionProvider.TryRead(principal, properties, out _).ShouldBeFalse();
    }
}
