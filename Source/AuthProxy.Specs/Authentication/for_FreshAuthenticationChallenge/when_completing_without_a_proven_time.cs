// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_FreshAuthenticationChallenge;

/// <summary>
/// Specifies that an authentication time is recorded only when a validated OIDC token proved it: OAuth completions and
/// OIDC tokens without a usable auth_time record nothing, never the local completion time.
/// </summary>
public class when_completing_without_a_proven_time : Specification
{
    readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1700000000);

    [Theory]
    [InlineData(false, "1699999990")]
    [InlineData(true, null)]
    [InlineData(true, "yesterday")]
    public void should_record_nothing(bool oidc, string? provenTime)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42"), new Claim("auth_time", "1699999990")], "provider"));
        var properties = new AuthenticationProperties();
        if (provenTime is not null) properties.Items[FreshAuthenticationChallenge.ValidatedTimeKey] = provenTime;

        FreshAuthenticationChallenge.Stamp(principal, properties, oidc);

        SessionAuthenticationTime.TryRead(principal, properties, out _).ShouldBeFalse();
        principal.HasClaim(_ => SessionClaims.IsReserved(_.Type)).ShouldBeFalse();
        properties.Items.ContainsKey(SessionAuthenticationTime.PropertyKey).ShouldBeFalse();
        properties.Items.ContainsKey(FreshAuthenticationChallenge.ValidatedTimeKey).ShouldBeFalse();
    }

    [Fact]
    public void should_not_validate_a_missing_time_into_the_session()
    {
        var properties = new AuthenticationProperties();

        FreshAuthenticationChallenge.ValidateOidc([], properties, _now).ShouldBeTrue();

        properties.Items.ContainsKey(FreshAuthenticationChallenge.ValidatedTimeKey).ShouldBeFalse();
    }

    [Fact]
    public void should_record_a_proven_time()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42")], "provider"));
        var properties = new AuthenticationProperties();
        properties.Items[FreshAuthenticationChallenge.ValidatedTimeKey] = _now.AddSeconds(-10).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

        FreshAuthenticationChallenge.Stamp(principal, properties, true);

        SessionAuthenticationTime.TryRead(principal, properties, out var time).ShouldBeTrue();
        time.ShouldEqual(_now.AddSeconds(-10));
    }
}
